use crate::{FilterListType, Record};

use std::io::Read;
use std::io::Write;

fn get_path_for_url(url: &str) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let mut path = std::path::PathBuf::from("data");
    path.push(std::path::PathBuf::from(url));
    path = path.with_file_name(path.file_name().unwrap_or(std::ffi::OsStr::new("data.txt")));
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?
    }
    Ok(path)
}

fn needs_updating(path: &std::path::Path, expires: u64) -> bool {
    if let Ok(metadata) = std::fs::metadata(path) {
        if let Ok(modified) = metadata.modified().or(metadata.created()) {
            let now = std::time::SystemTime::now();
            if let Ok(duration_since) = now.duration_since(modified) {
                return duration_since.as_secs() > expires;
            }
        }
    }
    true
}

async fn download_list_if_expired(
    client: &reqwest::Client,
    url: &str,
    expires: u64,
    list_type: FilterListType,
) -> Result<(FilterListType, String), Box<dyn std::error::Error>> {
    let path = get_path_for_url(url)?;
    if needs_updating(&path, expires) {
        if let Ok(response) = client.get(url).send().await {
            if let Ok(text) = response.text().await {
                println!("Downloaded: {:?}", url);
                let mut file = std::fs::File::create(path).unwrap();
                file.write_all(text.as_bytes()).unwrap();
                return Ok((list_type, text));
            }
        }
    }
    let mut file = std::fs::File::open(path)?;
    let mut text = String::new();
    file.read_to_string(&mut text)?;
    Ok((list_type, text))
}

pub async fn download_all(
    client: &reqwest::Client,
    records: &[Record],
) -> Vec<(FilterListType, String)> {
    let downloads: Vec<_> = records
        .iter()
        .map(|record| {
            download_list_if_expired(client, &record.url, record.expires, record.list_type)
        })
        .collect();
    futures::future::join_all(downloads)
        .await
        .into_iter()
        .filter_map(|x| x.ok())
        .collect()
}
