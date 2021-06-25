use crate::list_downloader::FilterListHandler;
use clap::Clap;
use domain_list_builder::*;
use rand::prelude::*;
use std::sync::Arc;

const LIST_CSV: &str = "filterlists.csv";

/// Blockconvert
#[derive(Clap)]
#[clap(version = "0.1")]
struct Opts {
    #[clap(subcommand)]
    mode: Mode,
    #[clap(short, long, default_value = "config.toml")]
    config: String,
}

#[derive(Clap)]
enum Mode {
    Generate,
    Query(Query),
    FindDomains,
}
#[derive(Clap)]
struct Query {
    query: String,
    #[clap(short, long)]
    ignore_dns: bool,
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

async fn generate(mut config: config::Config) -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    if let Ok(records) = read_csv() {
        println!("Read CSV");
        let builder = Arc::new(FilterListBuilder::new(config.clone()));
        println!("Initialised FilterListBuilder");

        list_downloader::download_all(
            config.clone(),
            client,
            records,
            get_internal_lists(),
            builder.clone(),
        )
        .await?;

        println!("Downloaded Lists");

        let builder = Arc::try_unwrap(builder).ok().expect("Failed to unwrap Arc");
        let bc = Arc::new(builder.to_filterlist());

        db::dir_db_read(
            bc.clone(),
            &std::path::Path::new(EXTRACTED_DOMAINS_DIR),
            config.get_max_extracted_age(),
        )
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
        bc.check_dns(&client).await;
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
    config: config::Config,
    parts: Vec<(Domain, Vec<Domain>, Vec<std::net::IpAddr>)>,
}

impl FilterListHandler for QueryFilterListHandler {
    fn handle_filter_list(&self, record: FilterListRecord, data: &str) {
        let bc = FilterList::from(self.config.clone(), &[(record.list_type, &data)]);
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

async fn query(mut config: config::Config, q: Query) -> Result<(), Box<dyn std::error::Error>> {
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
                config
                    .get_dns_servers()
                    .choose(&mut rand::thread_rng())
                    .unwrap()
                    .clone(),
                client.clone(),
                3_usize,
                config.get_timeout(),
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
    let query_handler = Arc::new(QueryFilterListHandler {
        config: config.clone(),
        parts,
    });
    let client = reqwest::Client::new();
    let records = read_csv()?;

    list_downloader::download_all(
        config,
        client,
        records,
        get_internal_lists(),
        query_handler.clone(),
    )
    .await?;
    Ok(())
}

async fn find_domains(config: config::Config) -> Result<(), Box<dyn std::error::Error>> {
    let mut ips = Default::default();
    if let Ok(records) = read_csv() {
        let client = reqwest::Client::new();
        let builder = Arc::new(FilterListBuilder::new(config.clone()));
        list_downloader::download_all(
            config.clone(),
            client,
            records,
            get_internal_lists(),
            builder.clone(),
        )
        .await?;
        let ips_lock = builder.extracted_ips.lock();
        ips = ips_lock.clone()
    };
    println!("Started finding domains");
    let _result = futures::future::join4(
        certstream::certstream(config.clone()),
        passive_dns::argus(ips.clone(), config.clone()),
        passive_dns::threatminer(ips.clone(), config.clone()),
        passive_dns::virus_total(ips.clone(), config.clone()),
    )
    .await;
    println!("Finished finding domains");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opts: Opts = Opts::parse();
    let config = config::Config::open(opts.config.clone())?;
    println!("Using config: {:?}", config);
    let result = match opts.mode {
        Mode::Generate => generate(config).await,
        Mode::Query(q) => query(config, q).await,
        Mode::FindDomains => find_domains(config).await,
    };
    if let Err(error) = &result {
        println!("Failed with error: {:?}", error);
    }
    result
}
