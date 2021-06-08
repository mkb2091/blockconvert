#[macro_use]
extern crate lazy_static;

pub mod certstream;
pub mod dns_lookup;
pub mod doh;
pub mod list_downloader;
pub mod passive_dns;

mod list_builder;

pub use list_builder::{FilterList, FilterListBuilder};

pub use blockconvert::{ipnet, Domain, DomainSetSharded};
pub type DomainSetShardedFX = DomainSetSharded<fxhash::FxBuildHasher>;

use serde::*;

use tokio::fs::OpenOptions;
use tokio::io::BufWriter;

use tokio::io::AsyncBufReadExt;
use tokio::io::AsyncWriteExt;

use tokio_stream::StreamExt;

use std::sync::Arc;

lazy_static! {
    static ref DOMAIN_REGEX: regex::Regex =
        regex::Regex::new("(?:[0-9A-Za-z-]+[.])+[0-9A-Za-z-]+").unwrap();
}

lazy_static! {
    static ref IP_REGEX: regex::Regex =
        regex::Regex::new("[12]?[0-9]{0,2}[.][12]?[0-9]{0,2}[.][12]?[0-9]{0,2}[.][12]?[0-9]{0,2}")
            .unwrap();
}

pub const EXTRACTED_DOMAINS_DIR: &str = "extracted";

pub const EXTRACTED_MAX_AGE: u64 = 30 * 86400;

pub fn get_blocked_domain_path() -> std::path::PathBuf {
    let mut path = std::path::PathBuf::from("output");
    path.push("domains.txt");
    path
}

pub fn get_adblock_path() -> std::path::PathBuf {
    let mut path = std::path::PathBuf::from("output");
    path.push("adblock.txt");
    path
}

pub fn get_hostfile_path() -> std::path::PathBuf {
    let mut path = std::path::PathBuf::from("output");
    path.push("hosts.txt");
    path
}

pub fn get_rpz_path() -> std::path::PathBuf {
    let mut path = std::path::PathBuf::from("output");
    path.push("domains.rpz");
    path
}

pub fn get_allowed_domain_path() -> std::path::PathBuf {
    let mut path = std::path::PathBuf::from("output");
    path.push("whitelist_domains.txt");
    path
}

pub fn get_allowed_adblock_path() -> std::path::PathBuf {
    let mut path = std::path::PathBuf::from("output");
    path.push("whitelist_adblock.txt");
    path
}

pub fn get_blocked_ips_path() -> std::path::PathBuf {
    let mut path = std::path::PathBuf::from("output");
    path.push("ip_blocklist.txt");
    path
}

pub fn get_allowed_ips_path() -> std::path::PathBuf {
    let mut path = std::path::PathBuf::from("output");
    path.push("allowed_ips.txt");
    path
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, PartialOrd, Eq, Ord)]
pub struct FilterListRecord {
    pub name: String,
    pub url: String,
    pub author: String,
    pub license: String,
    pub expires: u64,
    pub list_type: FilterListType,
}

impl FilterListRecord {
    pub fn from_type(list_type: FilterListType) -> Self {
        Self {
            name: Default::default(),
            url: Default::default(),
            author: Default::default(),
            license: Default::default(),
            expires: Default::default(),
            list_type,
        }
    }
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, PartialOrd, Eq, Ord)]
pub enum FilterListType {
    Adblock,
    DomainBlocklist,
    DomainAllowlist,
    IPBlocklist,
    IPAllowlist,
    IPNetBlocklist,
    DenyHosts,
    RegexAllowlist,
    RegexBlocklist,
    Hostfile,
    DNSRPZ,
    PrivacyBadger,
}

pub trait DBReadHandler: Send + Sync {
    fn handle_input(&self, data: &str);
    fn finished_with_file(&self) {}
}

pub struct DirectoryDB {
    path: std::path::PathBuf,
    wtr: BufWriter<tokio::fs::File>,
    max_age: u64,
}

impl DirectoryDB {
    pub async fn new(path: &std::path::Path, max_age: u64) -> Result<Self, std::io::Error> {
        let dir_path = std::path::PathBuf::from(path);
        let _ = tokio::fs::create_dir_all(&dir_path).await;

        let mut path = std::path::PathBuf::from(&dir_path);
        path.push(std::path::PathBuf::from(format!(
            "{:?}",
            chrono::Utc::today()
        )));
        let mut wtr = BufWriter::new(
            OpenOptions::new()
                .append(true)
                .create(true)
                .open(path)
                .await?,
        );
        wtr.write_all(b"\n").await?;
        Ok(Self {
            path: dir_path,
            wtr,
            max_age,
        })
    }
    pub async fn read<T: 'static + DBReadHandler>(
        &self,
        handle_input: Arc<T>,
    ) -> Result<(), std::io::Error> {
        let max_age = self.max_age;
        let _ = tokio::fs::create_dir_all(&self.path).await;
        let mut entries =
            tokio_stream::wrappers::ReadDirStream::new(tokio::fs::read_dir(&self.path).await?);

        let mut tasks: futures::stream::FuturesUnordered<_> =
            futures::stream::FuturesUnordered::new();
        println!("Started reading from files");
        while let Some(entry) = entries.next().await {
            let entry = entry?;
            let metadata = entry.metadata().await?;
            let path = entry.path();
            let handle_input = handle_input.clone();
            let task = tokio::task::spawn(async move {
                let mut record_count: usize = 0;
                if let Ok(modified) = metadata.modified().or_else(|_| metadata.created()) {
                    let now = std::time::SystemTime::now();
                    if let Ok(duration_since) = now.duration_since(modified) {
                        if duration_since.as_secs() < max_age {
                            if let Ok(file) = tokio::fs::File::open(&path).await {
                                let mut file = tokio::io::BufReader::new(file);
                                let mut line = String::new();
                                while let Ok(len) = file.read_line(&mut line).await {
                                    if len == 0 {
                                        break;
                                    }
                                    handle_input.handle_input(&line);
                                    line.clear();
                                    record_count += 1;
                                }
                            } else {
                                println!("Failed to read file: {:?}", &path);
                            }
                            if record_count != 0 {
                                println!(
                                    "Finished with file: {} with {} records",
                                    path.to_string_lossy(),
                                    record_count
                                );
                            }
                            handle_input.finished_with_file();
                            return;
                        }
                    }
                }
                println!("Removing expired record");
                if std::fs::remove_file(&path).is_err() {
                    println!("Failed to remove file: {:?}", path);
                };
            });
            tasks.push(task);
        }
        while tasks.next().await.is_some() {}
        Ok(())
    }

    pub async fn write_line(&mut self, line: &[u8]) -> Result<(), std::io::Error> {
        self.wtr.write_all(line).await?;
        self.wtr.write_all(b"\n").await?;
        Ok(())
    }
    pub async fn flush(&mut self) -> Result<(), std::io::Error> {
        self.wtr.flush().await?;
        Ok(())
    }
}
