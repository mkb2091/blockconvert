use crate::{config, FilterListRecord};
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio_stream::StreamExt;

fn get_path_for_url(url: &str) -> Result<std::path::PathBuf, std::io::Error> {
    let mut path = std::path::PathBuf::from("data");
    path.push(std::path::PathBuf::from(
        url.replace(':', "").replace('?', "").replace('=', ""),
    ));
    path = path.with_file_name(
        path.file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("data.txt")),
    );
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?
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
) -> Result<String, std::io::Error> {
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

                    if filetime::set_file_times(&path, target_time, target_time).is_err() {
                        println!("Failed to set file time for {:?}", record.url)
                    }
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
                    } else if let Ok(text) = response.text().await {
                        println!("Downloaded: {:?}", record.url);
                        let mut file = File::create(&path).await?;
                        file.write_all(text.as_bytes()).await?;
                        file.flush().await?;
                        drop(file);
                        set_last_modified(&last_modified);
                        return Ok(text);
                    } else {
                        println!("Failed to decode response for {}", record.url);
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
    Ok(tokio::fs::read_to_string(&path).await?)
}

pub trait FilterListHandler: Send + Sync {
    fn handle_filter_list(&self, record: FilterListRecord, data: &str);
}

pub async fn download_all<T: 'static + FilterListHandler>(
    mut config: config::Config,
    client: reqwest::Client,
    records: Vec<FilterListRecord>,
    local_filters: Vec<(std::path::PathBuf, FilterListRecord)>,
    handler: Arc<T>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut tasks: futures::stream::FuturesUnordered<_> = futures::stream::FuturesUnordered::new();

    for record in records {
        let handler = handler.clone();
        let client = client.clone();
        let timeout = config.get_timeout();
        let task = tokio::task::spawn(async move {
            match download_list_if_expired(timeout, client, &record).await {
                Ok(data) => handler.handle_filter_list(record, &data),
                Err(error) => println!(
                    "Failed to download filter list: {:?} with error {:?}",
                    record, error
                ),
            }
        });
        tasks.push(task);
    }

    for (file_path, record) in local_filters.into_iter() {
        let handler = handler.clone();
        let task = tokio::spawn(async move {
            match tokio::fs::read_to_string(&file_path).await {
                Ok(data) => handler.handle_filter_list(record, &data),
                Err(error) => println!("Failed to read list from disk with error: {:?}", error),
            }
        });
        tasks.push(task);
    }
    while tasks.next().await.is_some() {}

    Ok(())
}
