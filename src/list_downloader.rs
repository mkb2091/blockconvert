use crate::FilterListRecord;

use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio_stream::StreamExt;

#[derive(thiserror::Error, Debug)]
pub enum FilterListDownloadError {
    #[error(transparent)]
    PathCreationError(#[from] PathCreationError),
    #[error(transparent)]
    FileReadError(#[from] FileReadError),
    #[error(transparent)]
    FileWriteError(#[from] FileWriteError),
}

#[derive(thiserror::Error, Debug)]
#[error("Failed to create directory `{directory}`")]
pub struct PathCreationError {
    directory: std::path::PathBuf,
    #[source]
    source: std::io::Error,
}

#[derive(thiserror::Error, Debug)]
#[error("Failed to read file `{file}`")]
pub struct FileReadError {
    file: std::path::PathBuf,
    #[source]
    source: std::io::Error,
}

#[derive(thiserror::Error, Debug)]
#[error("Failed to write to file `file`")]
pub struct FileWriteError {
    file: std::path::PathBuf,
    #[source]
    source: std::io::Error,
}

fn get_path_for_url(url: &str) -> Result<std::path::PathBuf, PathCreationError> {
    let mut path = std::path::PathBuf::from("data");
    path.push(std::path::PathBuf::from(
        url.replace(':', "").replace('?', "").replace('=', ""),
    ));
    path = path.with_file_name(
        path.file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("data.txt")),
    );
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| PathCreationError {
            directory: parent.to_path_buf(),
            source,
        })?
    }
    Ok(path)
}

async fn get_last_update(path: &std::path::Path) -> Option<std::time::SystemTime> {
    let metadata = tokio::fs::metadata(path).await.ok()?;
    metadata.modified().or_else(|_| metadata.created()).ok()
}

fn parse_date(
    data: &str,
) -> Result<chrono::DateTime<chrono::FixedOffset>, chrono::format::ParseError> {
    chrono::DateTime::parse_from_rfc2822(data)
        .or_else(|_| chrono::DateTime::parse_from_rfc3339(data))
        .or_else(|_| data.parse())
}

#[test]
fn test_date_string_to_filetime() {
    assert!(parse_date("Mon, 03 Aug 2020 05:46:53 GMT").is_ok())
}

async fn download_list_if_expired(
    timeout: Option<std::time::Duration>,
    client: reqwest::Client,
    record: &FilterListRecord,
) -> Result<String, FilterListDownloadError> {
    let path = get_path_for_url(&record.url)?;
    let last_update = get_last_update(&path).await;
    if last_update
        .and_then(|modified| std::time::SystemTime::now().duration_since(modified).ok())
        .map(|duration_since| duration_since.as_secs() > record.expires)
        .unwrap_or(true)
    {
        let mut req = client.get(&record.url);
        if let Some(timeout) = timeout {
            req = req.timeout(timeout);
        }
        if let Some(last_update) = last_update {
            let date = chrono::DateTime::<chrono::Utc>::from(last_update);
            req = req.header(
                "if-modified-since",
                date.format("%a, %d %b %Y %H:%M:%S GMT").to_string(),
            );
        }
        if let Ok(response) = req.send().await {
            let headers = response.headers();
            let last_modified: Option<chrono::DateTime<chrono::FixedOffset>> = headers
                .get("last-modified")
                .and_then(|item| item.to_str().ok())
                .and_then(|last_modified| parse_date(last_modified).ok());

            let set_last_modified =
                |last_modified: &Option<chrono::DateTime<chrono::FixedOffset>>| {
                    let last_modified = last_modified.unwrap_or_else(|| chrono::Utc::now().into());
                    let target_time = filetime::FileTime::from_unix_time(
                        last_modified.timestamp(),
                        last_modified.timestamp_subsec_nanos(),
                    );

                    let _ = filetime::set_file_times(&path, target_time, target_time);
                };
            match response.status() {
                reqwest::StatusCode::OK => {
                    if last_modified
                        .as_ref()
                        .zip(last_update)
                        .map(|(last_modified, last_update)| {
                            last_modified <= &chrono::DateTime::<chrono::Utc>::from(last_update)
                        })
                        .unwrap_or(false)
                    {
                        println!("File unmodified: {}", record.url);
                    } else {
                        match response.bytes().await {
                            Ok(bytes) => {
                                println!("Downloaded: {:?}", record.url);
                                let text = String::from_utf8_lossy(&bytes).to_string();
                                let mut file =
                                    File::create(&path).await.map_err(|source| FileWriteError {
                                        file: path.to_path_buf(),
                                        source,
                                    })?;
                                file.write_all(text.as_bytes()).await.map_err(|source| {
                                    FileWriteError {
                                        file: path.to_path_buf(),
                                        source,
                                    }
                                });
                                file.flush().await.map_err(|source| FileWriteError {
                                    file: path.to_path_buf(),
                                    source,
                                })?;
                                drop(file);
                                set_last_modified(&last_modified);
                                return Ok(text);
                            }
                            Err(error) => {
                                println!(
                                    "Failed to decode response for {} with error: {:?}",
                                    record.url, error
                                );
                            }
                        }
                    }
                }
                reqwest::StatusCode::NOT_MODIFIED => {
                    println!("304 NOT MODIFIED: {}", record.url);
                    set_last_modified(&None)
                }
                status => println!("Unexpected status code: {:?} for {:?}", status, record.url),
            }
        } else {
            println!("Failed to fetch {}", record.url)
        }
    }
    Ok(tokio::fs::read_to_string(&path)
        .await
        .map_err(|source| FileReadError {
            file: path.to_path_buf(),
            source,
        })?)
}

pub trait FilterListHandler: Send + Sync {
    fn handle_filter_list(&self, record: FilterListRecord, data: &str);
}

pub fn download_all(
    timeout: Option<std::time::Duration>,
    client: reqwest::Client,
    records: Vec<FilterListRecord>,
    local_filters: Vec<(std::path::PathBuf, FilterListRecord)>,
) -> Vec<
    impl std::future::Future<Output = (FilterListRecord, Result<String, FilterListDownloadError>)>,
> {
    let local_filters = local_filters
        .into_iter()
        .map(|(path, record)| (Some(path), record));
    let records = records.into_iter().map(|record| (None, record));
    local_filters
        .chain(records)
        .map(|(path, record)| {
            let client = client.clone();
            async move {
                let data = if let Some(path) = path {
                    tokio::fs::read_to_string(&path)
                        .await
                        .map_err(|source| FileReadError { file: path, source }.into())
                } else {
                    download_list_if_expired(timeout, client, &record).await
                };
                (record, data)
            }
        })
        .collect::<Vec<_>>()
}
