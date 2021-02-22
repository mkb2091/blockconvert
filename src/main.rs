use tokio::fs::File;

use tokio::io::AsyncReadExt;

use rand::prelude::*;

use domain_list_builder::*;

const LIST_CSV: &str = "filterlists.csv";

use clap::Clap;

use std::sync::Arc;

use crate::list_downloader::FilterListHandler;

/// Blockconvert
#[derive(Clap)]
#[clap(version = "0.1")]
struct Opts {
    #[clap(subcommand)]
    mode: Mode,
}

#[derive(Clap)]
enum Mode {
    Generate,
    Query(Query),
    FindDomains(FindDomains),
}
#[derive(Clap)]
struct Query {
    query: String,
    #[clap(short, long)]
    ignore_dns: bool,
}

#[derive(Clap)]
struct FindDomains {
    #[clap(short, long)]
    virus_total_api: Option<String>,
}

const INTERNAL_LISTS: &[(&str, FilterListType)] = &[
    ("blocklist.txt", FilterListType::DomainBlocklist),
    ("block_ips.txt", FilterListType::IPBlocklist),
    ("block_regex.txt", FilterListType::RegexBlocklist),
    ("adblock.txt", FilterListType::Adblock),
    ("allowlist.txt", FilterListType::DomainAllowlist),
    ("allow_regex.txt", FilterListType::RegexAllowlist),
];

fn read_csv() -> Result<Vec<FilterListRecord>, csv::Error> {
    let path = std::path::Path::new(LIST_CSV);
    let mut records: Vec<FilterListRecord> = csv::Reader::from_path(path)?
        .deserialize()
        .map(|result| {
            let record: FilterListRecord = result?;
            Ok(record)
        })
        .filter_map(|result: Result<FilterListRecord, csv::Error>| result.ok())
        .collect();

    records.sort();
    records.reverse();
    records.dedup();
    let mut wrt = csv::Writer::from_path(path)?;
    for record in records.iter() {
        let _ = wrt.serialize(record);
    }
    let _ = wrt.flush();
    Ok(records)
}

async fn generate() -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let servers = [
        "https://dns.google/resolve".to_string(),
        "https://1.1.1.1/dns-query".to_string(),
    ];
    if let Ok(records) = read_csv() {
        println!("Read CSV");
        let builder = FilterListBuilder::new();
        println!("Initialised FilterListBuilder");
        list_downloader::download_all(client, records, builder.clone()).await?;
        println!("Downloaded lists");
        for (file_path, list_type) in INTERNAL_LISTS.iter() {
            let mut path = std::path::PathBuf::from("internal");
            path.push(file_path);
            if let Ok(mut file) = File::open(path).await {
                let mut text = String::new();
                let _ = file.read_to_string(&mut text).await;
                builder.add_list(*list_type, &text)
            }
        }
        let mut bc = builder.to_filterlist();
        DirectoryDB::new(
            &std::path::Path::new(EXTRACTED_DOMAINS_DIR),
            EXTRACTED_MAX_AGE,
        )
        .await?
        .read(bc.clone())
        .await?;
        bc.finished_extracting();
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::ACCEPT,
            "application/dns-json".parse().unwrap(),
        );
        let client = reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .unwrap();
        println!("Checking DNS");
        bc.check_dns(&servers, &client).await;
        println!("Writing to file");
        bc.write_all(
            &get_blocked_domain_path(),
            &get_hostfile_path(),
            &get_rpz_path(),
            &get_adblock_path(),
            &get_allowed_adblock_path(),
            &get_allowed_domain_path(),
            &get_blocked_ips_path(),
            &get_allowed_ips_path(),
        )
        .await?;
    }
    Ok(())
}

#[derive(Clone)]
struct QueryFilterListHandler {
    parts: Arc<Vec<(Domain, Vec<Domain>, Vec<std::net::IpAddr>)>>,
}

impl FilterListHandler for QueryFilterListHandler {
    fn handle_filter_list(&self, record: FilterListRecord, data: &str) {
        let bc = FilterList::from(&[(record.list_type, &data)]);
        for (part, cnames, ips) in self.parts.iter() {
            if let Some(allowed) = bc.allowed(&part, &cnames, &ips) {
                if allowed {
                    println!("ALLOW: {} allowed {}", record.url, part)
                } else {
                    println!("BLOCK: {} blocked {}", record.url, part)
                }
            }
        }
    }
}

async fn query(q: Query) -> Result<(), Box<dyn std::error::Error>> {
    let servers = [
        "https://dns.google/resolve".to_string(),
        "https://1.1.1.1/dns-query".to_string(),
    ];
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::ACCEPT,
        "application/dns-json".parse().unwrap(),
    );
    let client = reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .unwrap();
    let domain = q.query.parse::<Domain>()?;
    let mut parts: Vec<(Domain, Vec<Domain>, Vec<std::net::IpAddr>)> = Vec::new();
    for part in std::iter::once(domain.clone()).chain(domain.iter_parent_domains()) {
        let (cnames, ips): (Vec<Domain>, Vec<std::net::IpAddr>) = if !q.ignore_dns {
            if let Some(result) = doh::lookup_domain(
                Arc::new(servers.choose(&mut rand::thread_rng()).unwrap().clone()),
                client.clone(),
                3_usize,
                &part,
            )
            .await?
            {
                println!("Domain: {:?}", part);
                println!("CNames: {:?}", result.cnames);
                println!("IPs: {:?}", result.ips);
                (result.cnames, result.ips)
            } else {
                Default::default()
            }
        } else {
            Default::default()
        };
        parts.push((part, cnames, ips));
    }
    let query_handler = QueryFilterListHandler {
        parts: Arc::new(parts),
    };
    let client = reqwest::Client::new();
    if let Ok(records) = read_csv() {
        list_downloader::download_all(client, records, query_handler.clone()).await?;
    }
    for (file_path, list_type) in INTERNAL_LISTS.iter() {
        let mut path = std::path::PathBuf::from("internal");
        path.push(&file_path);
        if let Ok(mut file) = File::open(path).await {
            let mut text = String::new();
            let _ = file.read_to_string(&mut text).await;
            let mut record = FilterListRecord::from_type(*list_type);
            record.url = file_path.to_string();
            query_handler.handle_filter_list(record, &text);
        }
    }
    Ok(())
}

async fn find_domains(f: FindDomains) -> Result<(), Box<dyn std::error::Error>> {
    let mut ips = Default::default();
    if let Ok(records) = read_csv() {
        let client = reqwest::Client::new();
        let builder = FilterListBuilder::new();
        list_downloader::download_all(client, records, builder.clone()).await?;
        for (file_path, list_type) in INTERNAL_LISTS.iter() {
            let mut path = std::path::PathBuf::from("internal");
            path.push(file_path);
            if let Ok(mut file) = File::open(path).await {
                let mut text = String::new();
                let _ = file.read_to_string(&mut text).await;
                builder.add_list(*list_type, &text)
            }
        }
        let ips_lock = builder.extracted_ips.lock();
        ips = ips_lock.clone()
    };
    println!("Started finding domains");
    let base = futures::future::join3(
        certstream::certstream(),
        passive_dns::argus(ips.clone()),
        passive_dns::threatminer(ips.clone()),
    );
    if let Some(vt_api) = f.virus_total_api {
        let _result =
            futures::future::join(base, passive_dns::virus_total(ips.clone(), vt_api)).await;
    } else {
        let _result = base.await;
    }
    println!("Finished finding domains");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opts: Opts = Opts::parse();
    let result = match opts.mode {
        Mode::Generate => generate().await,
        Mode::Query(q) => query(q).await,
        Mode::FindDomains(f) => find_domains(f).await,
    };
    if let Err(error) = &result {
        println!("Failed with error: {:?}", error);
    }
    result
}
