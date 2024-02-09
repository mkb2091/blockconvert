use crate::list_downloader::FilterListHandler;
use clap::Parser;
use domain_list_builder::*;
use futures::FutureExt;
use futures::StreamExt;
use mimalloc::MiMalloc;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::str::FromStr;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Mutex;
use warp::Filter;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

const LIST_CSV: &str = "filterlists.csv";

/// Blockconvert
#[derive(Parser)]
#[clap(version = "0.1")]
struct Opts {
    #[clap(subcommand)]
    mode: Mode,
    #[clap(short, long, default_value = "config.toml")]
    config: std::path::PathBuf,
    #[clap(short, long, default_value = "db")]
    database: std::path::PathBuf,
}

#[derive(Parser)]
enum Mode {
    Generate(Generate),
    Query(Query),
    FindDomains(FindDomains),
}
#[derive(Parser)]
struct Query {
    query: String,
    #[clap(short, long)]
    ignore_dns: bool,
}
#[derive(Parser)]
struct FindDomains {
    #[clap(short, long, default_value = "64")]
    concurrent_requests: std::num::NonZeroUsize,
}

#[derive(Parser)]
struct Generate {
    #[clap(short, long, default_value = "5")]
    concurrent_downloads: std::num::NonZeroUsize,
    #[clap(short, long)]
    timeout: Option<f32>,
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

#[derive(Default)]
struct DnsRecord {
    ipv4: Vec<std::net::Ipv4Addr>,
    ipv6: Vec<std::net::Ipv6Addr>,
    cnames: Vec<String>,
    last_change: (),
}

#[derive(thiserror::Error, Debug)]
#[error("Database Empty")]
struct DatabaseEmptyError {}

async fn generate(db: sled::Db, gen_opts: Generate) -> Result<(), anyhow::Error> {
    let client = reqwest::Client::new();
    if let Ok(records) = read_csv() {
        println!("Read CSV");

        let mut tasks = list_downloader::download_all(
            gen_opts
                .timeout
                .map(|timeout| std::time::Duration::from_secs_f32(timeout)),
            client,
            records,
            get_internal_lists(),
        );

        println!("Started download with {} tasks", tasks.len());

        let mut spawned = futures::stream::FuturesUnordered::new();
        for _ in 0..gen_opts.concurrent_downloads.into() {
            if let Some(task) = tasks.pop() {
                spawned.push(tokio::spawn(task));
            }
        }

        let builder = FilterListBuilder::new();

        while let Some(result) = spawned.next().await {
            let (record, data) = result?;
            let data = data?;

            if let Some(task) = tasks.pop() {
                spawned.push(tokio::spawn(task));
            }
            builder.add_list(record.list_type, &data);
        }

        println!("Parsed all domain lists");
        let mut first_bytes = [0; 8];
        let (first, _) = db.first()?.ok_or(DatabaseEmptyError {})?;
        first_bytes[..first.len().min(8)].copy_from_slice(&first[..first.len().min(8)]);

        let mut last_bytes = [u8::MAX; 8];
        let (last, _) = db.last()?.ok_or(DatabaseEmptyError {})?;
        last_bytes[..last.len().min(8)].copy_from_slice(&last[..last.len().min(8)]);

        println!(
            "first: {:?}, last: {:?}",
            std::str::from_utf8(&first),
            std::str::from_utf8(&last)
        );

        let mut ranges = VecDeque::new();
        ranges.push_back((
            u64::from_be_bytes(first_bytes),
            u64::from_be_bytes(last_bytes).saturating_add(1),
        ));
        let ranges = Arc::new(Mutex::new(ranges));

        let scanned_count = Arc::new(AtomicUsize::new(0));
        let mut threads = Vec::<std::thread::JoinHandle<anyhow::Result<()>>>::new();
        let buffer_size = num_cpus::get();
        let batch_size = 1000;
        for _ in 0..num_cpus::get() {
            let scanned_count = scanned_count.clone();
            let db = db.clone();

            let ranges = ranges.clone();
            let thread = std::thread::spawn(move || {
                loop {
                    let (start, end) = {
                        let mut ranges = ranges.lock().unwrap();

                        let Some((start, mut end)) = ranges.pop_front() else {
                            break;
                        };
                        while ranges.len() < buffer_size && end - start > 1 {
                            let mid = start + (end - start) / 2;
                            ranges.push_back((mid, end));
                            end = mid;
                        }
                        (start, end)
                    };

                    let mut local_scanned_count = 0;
                    let start_bytes = start.to_be_bytes();
                    let min_next_start = (start + 1).to_be_bytes();
                    let end_bytes = end.to_be_bytes();
                    let mut last_item = None;
                    for item in db.range(start_bytes..end_bytes) {
                        let (domain, _data) = item?;
                        local_scanned_count += 1;
                        if let Ok(_domain) = std::str::from_utf8(&domain) {
                            //println!("{}", domain);
                        }
                        if local_scanned_count >= batch_size && &domain[..] > &min_next_start[..] {
                            last_item = Some(domain);
                            break;
                        }
                    }

                    if local_scanned_count >= batch_size {
                        if let Some(last_item) = last_item {
                            let mut first_bytes = [0; 8];
                            first_bytes[..last_item.len().min(8)]
                                .copy_from_slice(&last_item[..last_item.len().min(8)]);
                            let new_start = u64::from_be_bytes(first_bytes);
                            ranges.lock().unwrap().push_back((new_start, end));
                        }
                    }

                    if local_scanned_count != 0 {
                        scanned_count.fetch_add(local_scanned_count, Ordering::SeqCst);
                    }
                }

                Ok(())
            });
            threads.push(thread);
        }

        let now = std::time::Instant::now();
        for thread in threads {
            thread.join().unwrap()?;
        }

        println!(
            "Scanned {} domains in {}",
            scanned_count.load(Ordering::SeqCst),
            now.elapsed().as_secs_f32()
        );

        /*


        let bc = Arc::new(builder.to_filterlist());

        db::dir_db_read(
            bc.clone(),
            &std::path::Path::new(&config.get_paths().extracted),
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
        let now = std::time::Instant::now();
        bc.check_dns(&client).await;
        println!("Checked DNS in {}s", now.elapsed().as_secs_f32());
        println!("Writing to file");
        let now = std::time::Instant::now();
        bc.write_all().await?;
        println!("Wrote to file in {}s", now.elapsed().as_secs_f32());*/
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

async fn query(_config: config::Config, _q: Query) -> Result<(), anyhow::Error> {
    /*let mut headers = reqwest::header::HeaderMap::new();
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
    .await?;*/
    Ok(())
}

async fn find_domains(
    find_opts: FindDomains,
    db: sled::Db,
    resolver: trust_dns_resolver::TokioAsyncResolver,
) -> Result<(), anyhow::Error> {
    println!("Started finding domains");
    let (tx, rx) = std::sync::mpsc::channel::<Domain>();
    let db_clone = db.clone();
    let current_lookups = Arc::new(dashmap::DashSet::<Domain>::new());
    let current_lookups_clone = current_lookups.clone();

    let (resolve_tx, mut resolve_rx) = tokio::sync::mpsc::unbounded_channel::<Domain>();
    std::thread::spawn(move || {
        let current_lookups = current_lookups_clone;
        let mut counter: u64 = 0;
        while let Ok(domain) = rx.recv() {
            if !current_lookups.contains(&domain) {
                current_lookups.insert(domain.clone());

                let old = db_clone.get(domain.as_str());
                if old == Ok(None) {
                    counter += 1;

                    if resolve_tx.send(domain).is_err() {
                        break;
                    }
                }
            }
        }
    });
    #[derive(Serialize, Deserialize)]
    struct DnsRecord {
        ips: Vec<std::net::IpAddr>,
        cnames: Vec<String>,
    }

    let (write_tx, write_rx) = std::sync::mpsc::channel::<(Domain, DnsRecord)>();
    let dns_task = tokio::task::spawn(async move {
        let mut tasks = futures::stream::FuturesUnordered::new();
        while let Some(domain) = resolve_rx.recv().await {
            let resolver = resolver.clone();
            let write_tx = write_tx.clone();
            let task = tokio::spawn(async move {
                let mut host = domain.to_string();
                host.push('.');
                if let Ok(response) = resolver.lookup_ip(host).await {
                    let ips = response.iter().collect::<Vec<std::net::IpAddr>>();
                    let cnames = response
                        .as_lookup()
                        .record_iter()
                        .filter_map(|record| {
                            if let Some(trust_dns_resolver::proto::rr::record_data::RData::CNAME(
                                name,
                            )) = record.data()
                            {
                                Domain::from_str(&name.to_string().trim_end_matches('.')).ok()
                            } else {
                                None
                            }
                        })
                        .map(|domain| domain.to_string())
                        .collect::<Vec<_>>();

                    let record = DnsRecord { ips, cnames };
                    write_tx.send((domain, record))?;
                }
                Ok::<_, anyhow::Error>(())
            });
            tasks.push(task);
            if tasks.len() >= find_opts.concurrent_requests.into() {
                let _ = tasks.next().await;
            }
        }
        while let Some(_) = tasks.next().await {}
    });
    {
        let db = db.clone();
        std::thread::spawn(move || {
            while let Ok((domain, record)) = write_rx.recv() {
                let bytes = bincode::serialize(&record).unwrap();
                db.insert(domain.as_str(), bytes).unwrap();

                current_lookups.remove(&domain);
            }
        });
    }
    futures::select!(
        _ = tokio::task::spawn(certstream::certstream(tx)).fuse() => (),
        _ = tokio::task::spawn(async {
            let _ = tokio::signal::ctrl_c().await;
            println!("Recieved Ctrl-C");
        }).fuse() => (),
        _ = dns_task.fuse() => ()
    );
    db.flush_async().await?;

    println!("Finished finding domains");
    println!("Disk size: {:?}", db.size_on_disk());
    Ok(())
}

fn main2() -> Result<(), anyhow::Error> {
    let opts: Opts = Opts::parse();

    let gen_opts = {
        if let Mode::Generate(gen_opts) = opts.mode {
            gen_opts
        } else {
            panic!()
        }
    };

    let client = reqwest::Client::new();
    if let Ok(records) = read_csv() {
        println!("Read CSV");

        {
            let tasks = list_downloader::download_all(
                gen_opts
                    .timeout
                    .map(|timeout| std::time::Duration::from_secs_f32(timeout)),
                client.clone(),
                records.clone(),
                get_internal_lists(),
            );

            let semaphore = tokio::sync::Semaphore::new(gen_opts.concurrent_downloads.into());
            let _tasks = tasks.into_iter().map(|task| async {
                let _ = semaphore.acquire().await?;

                let (record, data) = tokio::spawn(task).await?;
                let _data = data?;

                let filter_list = ();

                Ok::<_, anyhow::Error>((record, filter_list))
            });
        }

        let mut tasks = list_downloader::download_all(
            gen_opts
                .timeout
                .map(|timeout| std::time::Duration::from_secs_f32(timeout)),
            client,
            records,
            get_internal_lists(),
        );

        println!("Started download with {} tasks", tasks.len());

        let mut spawned = Vec::new();
        for _ in 0..gen_opts.concurrent_downloads.into() {
            let (_tx, _rx) = tokio::sync::mpsc::unbounded_channel::<()>();

            if let Some(task) = tasks.pop() {
                spawned.push(tokio::spawn(async {
                    let (record, data) = task.await;

                    (record, data)
                }));
            }
        }

        let builder = FilterListBuilder::new();
        let _x = async {
            while let Some(result) = spawned.pop() {
                let result = result.await;
                let (record, data) = result?;
                let data = data?;

                if let Some(task) = tasks.pop() {
                    spawned.push(tokio::spawn(task));
                }
                builder.add_list(record.list_type, &data);
            }
            Ok::<(), Box<dyn std::error::Error>>(())
        };
    }
    let opts: Opts = Opts::parse();

    let db = sled::Config::default()
        .mode(sled::Mode::HighThroughput)
        .path(opts.database.clone())
        .open()?;

    let resolver_config = trust_dns_resolver::config::ResolverConfig::default();
    let mut resolver_opts = trust_dns_resolver::config::ResolverOpts::default();
    resolver_opts.use_hosts_file = false;
    resolver_opts.preserve_intermediates = true;
    let resolver = trust_dns_resolver::TokioAsyncResolver::tokio(resolver_config, resolver_opts)?;

    let rt = tokio::runtime::Runtime::new()?;

    rt.block_on(async move {
        match opts.mode {
            Mode::Generate(g) => generate(db, g).await,
            Mode::Query(q) => query(config::Config::open(opts.config.clone())?, q).await,
            Mode::FindDomains(find_opts) => find_domains(find_opts, db, resolver).await,
        }
    })
}

#[derive(Clone, Debug)]
pub struct FilterListManager {
    path: Box<std::path::Path>,
    lists: tokio::sync::OnceCell<Vec<FilterListRecord>>,
}

impl FilterListManager {
    pub fn new(path: &std::path::Path) -> Self {
        Self {
            path: path.to_owned().into_boxed_path(),
            lists: tokio::sync::OnceCell::new(),
        }
    }

    async fn load_lists(&self) -> Result<Vec<FilterListRecord>, anyhow::Error> {
        let contents = tokio::fs::read_to_string(&self.path).await?;
        let records = csv::Reader::from_reader(contents.as_bytes())
            .deserialize::<FilterListRecord>()
            .collect::<Result<Vec<FilterListRecord>, _>>()?;

        Ok(records)
    }

    pub async fn get_lists(&self) -> Result<Vec<FilterListRecord>, anyhow::Error> {
        let lists = self
            .lists
            .get_or_try_init(|| async { self.load_lists().await })
            .await?;

        Ok(lists.clone())
    }
}

#[derive(Parser)]
#[clap(version = "0.1")]
struct AppOpts {
    #[clap(short, long, default_value = "filterlists.csv")]
    filter_lists: std::path::PathBuf,
}

#[tokio::main]
async fn main() {
    let opts = AppOpts::parse();

    let list_manager = Arc::new(FilterListManager::new(&opts.filter_lists));

    //parse args
    //open db
    //start certstream domains
    //integrate pihole logs to find more domains
    //web scraper?
    //reverse dns lookup
    //passive dns

    //generate prometheus stats

    let index = warp::path::end().and(warp::fs::file("index.html"));
    let js = warp::path("frontend.js").and(warp::fs::file("frontend/pkg/frontend.js"));
    let wasm = warp::path("frontend_bg.wasm").and(warp::fs::file("frontend/pkg/frontend_bg.wasm"));

    let lists = warp::path("filter-lists").and(warp::path("view").then(move || {
        let list_manager = list_manager.clone();
        async move {
            let list_manager = list_manager.clone();
            let lists = list_manager.get_lists().await.ok();
            let encoded = bincode::serialize(&lists).unwrap();
            encoded
        }
    }));

    let unknown = warp::path::tail().map(|tail| {
        log::info!("Unknown URL: {:?}", tail);
        "404"
    });
    let site = index.or(js).or(wasm).or(lists).or(unknown);
    //let site = site.with(warp::filters::compression::brotli());
    //let site = site.with(warp::filters::compression::gzip());
    //let site = site.with(warp::filters::compression::deflate());

    warp::serve(site).run(([127, 0, 0, 1], 3030)).await;
}
