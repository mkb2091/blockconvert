#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

use async_std::fs::File;

use async_std::prelude::*;

use rand::prelude::*;

use ::blockconvert::*;

const LIST_CSV: &str = "filterlists.csv";

use clap::Clap;

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

const INERNAL_LISTS: &[(&str, FilterListType)] = &[
    ("blocklist.txt", FilterListType::DomainBlocklist),
    ("block_regex.txt", FilterListType::RegexBlocklist),
    ("allowlist.txt", FilterListType::DomainAllowlist),
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
        "https://dns.google.com/resolve".to_string(),
        "https://cloudflare-dns.com/dns-query".to_string(),
    ];
    if let Ok(records) = read_csv() {
        let mut builder = BlockConvertBuilder::new();
        list_downloader::download_all(&client, &records, |record, data| {
            builder.add_list(record.list_type, data);
        })
        .await;
        for (file_path, list_type) in INERNAL_LISTS.iter() {
            let mut path = std::path::PathBuf::from("internal");
            path.push(file_path);
            if let Ok(mut file) = File::open(path).await {
                let mut text = String::new();
                let _ = file.read_to_string(&mut text).await;
                builder.add_list(*list_type, &text)
            }
        }
        let mut bc = builder.to_blockconvert();
        DirectoryDB::new(
            &std::path::Path::new(EXTRACTED_DOMAINS_DIR),
            EXTRACTED_MAX_AGE,
        )
        .await?
        .read(|line| {
            if let Ok(domain) = line.trim().parse::<Domain>() {
                bc.add_extracted_domain(domain);
            }
        })
        .await?;
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::ACCEPT,
            "application/dns-json".parse().unwrap(),
        );
        let client = reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .unwrap();
        bc.check_dns(&servers, &client).await;
        bc.write_all(
            &get_blocked_domain_path(),
            &get_hostfile_path(),
            &get_rpz_path(),
            &get_adblock_path(),
            &get_allowed_domain_path(),
            &get_blocked_ips_path(),
            &get_allowed_ips_path(),
        )
        .await?;
    }
    Ok(())
}

async fn query(q: Query) -> Result<(), Box<dyn std::error::Error>> {
    let servers = [
        "https://dns.google.com/resolve".to_string(),
        "https://cloudflare-dns.com/dns-query".to_string(),
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
                servers.choose(&mut rand::thread_rng()).unwrap(),
                &client,
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

    let client = reqwest::Client::new();
    let check_filter_list = |url: &str, list_type: FilterListType, data: &str| {
        let bc = BlockConvert::from(&[(list_type, &data)]);
        for (part, cnames, ips) in parts.iter() {
            if let Some(allowed) = bc.allowed(&part, &cnames, &ips) {
                if allowed {
                    println!("ALLOW: {} allowed {}", url, part)
                } else {
                    println!("BLOCK: {} blocked {}", url, part)
                }
            }
        }
    };
    if let Ok(records) = read_csv() {
        list_downloader::download_all(&client, &records, |record, data| {
            check_filter_list(&record.url, record.list_type, &data);
        })
        .await;
    }
    for (file_path, list_type) in INERNAL_LISTS.iter() {
        let mut path = std::path::PathBuf::from("internal");
        path.push(&file_path);
        if let Ok(mut file) = File::open(path).await {
            let mut text = String::new();
            let _ = file.read_to_string(&mut text).await;
            check_filter_list(&file_path, *list_type, &text);
        }
    }
    Ok(())
}

async fn find_domains(f: FindDomains) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(vt_api) = f.virus_total_api {
        let _result = futures::join!(
            certstream::certstream(),
            passive_dns::argus(),
            passive_dns::threatminer(),
            passive_dns::virus_total(vt_api)
        );
    } else {
        let _result = futures::join!(
            certstream::certstream(),
            passive_dns::argus(),
            passive_dns::threatminer()
        );
    }

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
