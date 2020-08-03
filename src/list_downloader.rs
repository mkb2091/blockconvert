use crate::FilterListRecord;

use async_std::fs::File;
use async_std::prelude::*;

fn get_path_for_url(url: &str) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let mut path = std::path::PathBuf::from("data");
    path.push(std::path::PathBuf::from(url));
    path = path.with_file_name(
        path.file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("data.txt")),
    );
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?
    }
    Ok(path)
}

async fn needs_updating(path: &std::path::Path, expires: u64) -> bool {
    if let Ok(metadata) = async_std::fs::metadata(path).await {
        if let Ok(modified) = metadata.modified().or_else(|_| metadata.created()) {
            let now = std::time::SystemTime::now();
            if let Ok(duration_since) = now.duration_since(modified) {
                return duration_since.as_secs() > expires;
            }
        }
    }
    true
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
    client: &reqwest::Client,
    record: FilterListRecord,
) -> Result<(FilterListRecord, String), Box<dyn std::error::Error>> {
    let path = get_path_for_url(&record.url)?;
    if needs_updating(&path, record.expires).await {
        if let Ok(response) = client.get(&record.url).send().await {
            let headers = response.headers();
            // let etag = headers.get("etag").clone();
            let last_modified: Option<String> = headers
                .get("last-modified")
                .and_then(|item| item.to_str().ok())
                .map(|item| item.to_string());
            if let Ok(text) = response.text().await {
                println!("Downloaded: {:?}", record.url);
                // println!("Etag: {:?}", etag);
                // println!("last_modified: {:?}", last_modified);
                let mut file = File::create(&path).await?;
                file.write_all(text.as_bytes()).await?;
                file.flush().await?;
                drop(file);
                if let Some(last_modified) = last_modified {
                    if let Ok(target_time) = date_string_to_filetime(&last_modified) {
                        if filetime::set_file_times(&path, target_time, target_time).is_err() {
                            println!("Failed to set file time for {:?}", record.url)
                        }
                    } else {
                        println!("Failed to decode date: {:?}", last_modified);
                    }
                }
                return Ok((record, text));
            } else {
                println!("Failed to decode response for {}", record.url);
            }
        } else {
            println!("Failed to fetch {}", record.url)
        }
    }
    let mut file = File::open(path).await?;
    let mut text = String::new();
    file.read_to_string(&mut text).await?;
    Ok((record, text))
}

pub async fn download_all<F>(
    client: &reqwest::Client,
    records: &[FilterListRecord],
    mut f: F,
) -> Result<(), Box<dyn std::error::Error>>
where
    F: FnMut(FilterListRecord, &str),
{
    let mut downloads = futures::stream::FuturesUnordered::new();
    for record in records {
        downloads.push(download_list_if_expired(client, record.clone()))
    }
    while let Some(data) = downloads.next().await {
        let (record, data) = data?;
        f(record, &data)
    }
    Ok(())
}
