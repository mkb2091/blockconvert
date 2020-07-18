#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

use async_std::fs::File;

use async_std::prelude::*;

use rand::prelude::*;

use blockconvert::{
    list_downloader, BlockConvert, BlockConvertBuilder, Domain, FilterListRecord, FilterListType,
};

const LIST_CSV: &'static str = "filterlists.csv";

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
}
#[derive(Clap)]
struct Query {
    query: String,
    #[clap(short, long)]
    ignore_dns: bool,
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

async fn generate() {
    let client = reqwest::Client::new();
    let servers = [
        "https://dns.google.com/resolve".to_string(),
        "https://cloudflare-dns.com/dns-query".to_string(),
    ];
    if let Ok(records) = read_csv() {
        let mut builder = BlockConvertBuilder::new();
        list_downloader::download_all(&client, &records, |list_type, data| {
            builder.add_list(list_type, data)
        })
        .await;

        for (file_path, list_type) in &[
            ("blocklist.txt", FilterListType::DomainBlocklist),
            ("allowlist.txt", FilterListType::DomainAllowlist),
        ] {
            let mut path = std::path::PathBuf::from("internal");
            path.push(file_path);
            if let Ok(mut file) = File::open(path).await {
                let mut text = String::new();
                let _ = file.read_to_string(&mut text).await;
                builder.add_list(*list_type, &text)
            }
        }
        let mut bc = builder.to_blockconvert();
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
        let _ = bc
            .write_all(
                &std::path::Path::new("output/blocked_domains.txt"),
                &std::path::Path::new("output/allowed_domains.txt"),
                &std::path::Path::new("output/blocked_ips.txt"),
                &std::path::Path::new("output/allowed_ips.txt"),
            )
            .await;
    }
}

async fn query(q: Query) {
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
    let domain = if let Ok(domain) = q.query.parse::<Domain>() {
        domain
    } else {
        println!("Failed to parse domain");
        return;
    };
    let (cnames, ips): (Vec<Domain>, Vec<std::net::IpAddr>) = if !q.ignore_dns {
        if let Ok(dns_result) = blockconvert::doh::lookup_domain(
            servers.choose(&mut rand::thread_rng()).unwrap(),
            &client,
            3_usize,
            &domain,
        )
        .await
        {
            if let Some(result) = dns_result {
                println!("CNames: {:?}", result.cnames);
                println!("IPs: {:?}", result.ips);
                (result.cnames, result.ips)
            } else {
                Default::default()
            }
        } else {
            println!("Failed to lookup DNS");
            return;
        }
    } else {
        Default::default()
    };

    let client = reqwest::Client::new();
    let check_filter_list = |url: &str, list_type: FilterListType, data: &str| {
        let bc = BlockConvert::from(&[(list_type, &data)]);
        for part in std::iter::once(domain.clone()).chain(domain.iter_parent_domains()) {
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
        for record in records.iter() {
            if let Ok((list_type, data)) = blockconvert::list_downloader::download_list_if_expired(
                &client,
                &record.url,
                record.expires,
                record.list_type,
            )
            .await
            {
                check_filter_list(&record.url, list_type, &data);
            }
        }
    }
    for (file_path, list_type) in &[
            ("blocklist.txt", FilterListType::DomainBlocklist),
            ("allowlist.txt", FilterListType::DomainAllowlist),
        ] {
            let mut path = std::path::PathBuf::from("internal");
            path.push(&file_path);
            if let Ok(mut file) = File::open(path).await {
                let mut text = String::new();
                let _ = file.read_to_string(&mut text).await;
                check_filter_list(&file_path, *list_type, &text);
            }
        }
}

fn main() {
    let mut rt = tokio::runtime::Runtime::new().unwrap();

    let opts: Opts = Opts::parse();
    rt.block_on(async {
        match opts.mode {
            Mode::Generate => generate().await,
            Mode::Query(q) => query(q).await,
        }
    })
}
