use crate::FilterListRecord;

use tokio::fs::File;

use tokio::io::AsyncWriteExt;
use tokio_stream::StreamExt;

use std::sync::Arc;

fn get_path_for_url(url: &str) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
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

fn date_string_to_filetime(data: &str) -> Result<filetime::FileTime, Box<dyn std::error::Error>> {
    let date: chrono::DateTime<chrono::FixedOffset> = chrono::DateTime::parse_from_rfc2822(data)
        .or_else(|_| chrono::DateTime::parse_from_rfc3339(data))
        .or_else(|_| data.parse())?;
    Ok(filetime::FileTime::from_unix_time(
        date.timestamp(),
        date.timestamp_subsec_nanos(),
    ))
}

#[test]
fn test_date_string_to_filetime() {
    assert!(date_string_to_filetime("Mon, 03 Aug 2020 05:46:53 GMT").is_ok())
}

async fn download_list_if_expired(
    client: reqwest::Client,
    record: FilterListRecord,
) -> Result<String, Box<dyn std::error::Error>> {
    let path = get_path_for_url(&record.url)?;
    let last_update = get_last_update(&path).await;
    if last_update
        .and_then(|modified| std::time::SystemTime::now().duration_since(modified).ok())
        .map(|duration_since| duration_since.as_secs() > record.expires)
        .unwrap_or(true)
    {
        let mut req = client.get(&record.url);
        if let Some(last_update) = last_update {
            let date = chrono::DateTime::<chrono::Utc>::from(last_update);
            req = req.header("if-modified-since", date.to_rfc2822());
        }
        if let Ok(response) = req.send().await {
            let headers = response.headers();
            let last_modified: Option<String> = headers
                .get("last-modified")
                .and_then(|item| item.to_str().ok())
                .map(|item| item.to_string());
            let set_last_modified = |last_modified: &Option<String>| {
                if let Some(last_modified) = last_modified {
                    if let Ok(target_time) = date_string_to_filetime(&last_modified) {
                        if filetime::set_file_times(&path, target_time, target_time).is_err() {
                            println!("Failed to set file time for {:?}", record.url)
                        }
                    } else {
                        println!("Failed to decode date: {:?}", last_modified);
                    }
                }
            };
            match response.status() {
                reqwest::StatusCode::OK => {
                    if let Ok(text) = response.text().await {
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
                    set_last_modified(&last_modified)
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
    client: reqwest::Client,
    records: Vec<FilterListRecord>,
    handler: Arc<T>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut downloads: futures::stream::FuturesUnordered<_> =
        futures::stream::FuturesUnordered::new();

    for record in records {
        let handler = handler.clone();
        let client = client.clone();
        let task = tokio::task::spawn(async move {
            match download_list_if_expired(client, record.clone()).await {
                Ok(data) => {
                    tokio::task::block_in_place(|| handler.handle_filter_list(record, &data))
                }
                Err(error) => println!(
                    "Failed to download filter list: {:?} with error {:?}",
                    record, error
                ),
            }
        });
        downloads.push(task);
    }
    while downloads.next().await.is_some() {}
    Ok(())
}
