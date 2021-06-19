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
    Generate(Generate),
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
    #[clap(short, long)]
    extracted_max_age: u64,
}

#[derive(Clap)]
struct Generate {
    #[clap(short, long)]
    concurrent_requests: usize,
    #[clap(short, long)]
    dns_max_age: u64,
    #[clap(short, long)]
    extracted_max_age: u64,
}

const INTERNAL_LISTS: &[(&str, FilterListType)] = &[
    ("blocklist.txt", FilterListType::DomainBlocklist),
    ("block_ips.txt", FilterListType::IPBlocklist),
    ("block_ipnets.txt", FilterListType::IPNetBlocklist),
    ("block_regex.txt", FilterListType::RegexBlocklist),
    ("adblock.txt", FilterListType::Adblock),
    ("allowlist.txt", FilterListType::DomainAllowlist),
    ("allow_regex.txt", FilterListType::RegexAllowlist),
];

fn get_internal_lists() -> Vec<(std::path::PathBuf, FilterListRecord)> {
    let mut internal = Vec::new();
    for (file_path, list_type) in INTERNAL_LISTS.iter() {
        let mut path = std::path::PathBuf::from("internal");
        path.push(file_path);
        let record = FilterListRecord {
            name: file_path.to_string(),
            url: file_path.to_string(),
            author: Default::default(),
            license: Default::default(),
            expires: Default::default(),
            list_type: *list_type,
        };
        internal.push((path, record));
    }
    internal
}

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

async fn generate(opts: Generate) -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let servers = [
        "https://dns.google/resolve".to_string(),
        "https://1.1.1.1/dns-query".to_string(),
    ];
    if let Ok(records) = read_csv() {
        println!("Read CSV");
        let builder = Arc::new(FilterListBuilder::new());
        println!("Initialised FilterListBuilder");

        list_downloader::download_all(client, records, get_internal_lists(), builder.clone())
            .await?;

        println!("Downloaded Lists");

        let builder = Arc::try_unwrap(builder).ok().expect("Failed to unwrap Arc");
        let bc = Arc::new(builder.to_filterlist());
        DirectoryDB::new(
            &std::path::Path::new(EXTRACTED_DOMAINS_DIR),
            opts.extracted_max_age,
        )
        .await?
        .read(bc.clone())
        .await?;
        bc.finished_extracting();
        let mut bc = Arc::try_unwrap(bc).ok().expect("Failed to unwrap Arc");
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
        bc.check_dns(
            &servers,
            &client,
            opts.concurrent_requests,
            opts.dns_max_age,
        )
        .await;
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
    parts: Vec<(Domain, Vec<Domain>, Vec<std::net::IpAddr>)>,
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
    let query_handler = Arc::new(QueryFilterListHandler { parts });
    let client = reqwest::Client::new();
    let records = read_csv()?;

    list_downloader::download_all(client, records, get_internal_lists(), query_handler.clone())
        .await?;
    Ok(())
}

async fn find_domains(f: FindDomains) -> Result<(), Box<dyn std::error::Error>> {
    let mut ips = Default::default();
    if let Ok(records) = read_csv() {
        let client = reqwest::Client::new();
        let builder = Arc::new(FilterListBuilder::new());
        list_downloader::download_all(client, records, get_internal_lists(), builder.clone())
            .await?;
        let ips_lock = builder.extracted_ips.lock();
        ips = ips_lock.clone()
    };
    println!("Started finding domains");
    let base = futures::future::join3(
        certstream::certstream(),
        passive_dns::argus(ips.clone(), f.extracted_max_age),
        passive_dns::threatminer(ips.clone(), f.extracted_max_age),
    );
    if let Some(vt_api) = f.virus_total_api {
        let _result = futures::future::join(
            base,
            passive_dns::virus_total(ips.clone(), vt_api, f.extracted_max_age),
        )
        .await;
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
        Mode::Generate(g) => generate(g).await,
        Mode::Query(q) => query(q).await,
        Mode::FindDomains(f) => find_domains(f).await,
    };
    if let Err(error) = &result {
        println!("Failed with error: {:?}", error);
    }
    result
}
