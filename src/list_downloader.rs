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

pub async fn download_list_if_expired(
    client: &reqwest::Client,
    record: FilterListRecord,
) -> Result<(FilterListRecord, String), Box<dyn std::error::Error>> {
    let path = get_path_for_url(&record.url)?;
    if needs_updating(&path, record.expires).await {
        if let Ok(response) = client.get(&record.url).send().await {
            if let Ok(text) = response.text().await {
                println!("Downloaded: {:?}", record.url);
                let mut file = File::create(path).await?;
                file.write_all(text.as_bytes()).await?;
                return Ok((record, text));
            }
        }
    }
    let mut file = File::open(path).await?;
    let mut text = String::new();
    file.read_to_string(&mut text).await?;
    Ok((record, text))
}

pub async fn download_all<F>(client: &reqwest::Client, records: &[FilterListRecord], mut f: F)
where
    F: FnMut(FilterListRecord, &str),
{
    let mut downloads = futures::stream::FuturesUnordered::new();
    for record in records {
        downloads.push(download_list_if_expired(client, record.clone()))
    }
    while let Some(Ok((record, data))) = downloads.next().await {
        f(record, &data)
    }
}
