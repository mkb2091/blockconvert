use std::str::FromStr;

use tokio_stream::StreamExt;

use crate::{doh, DBReadHandler, DirectoryDB, Domain, DomainSetShardedDefault};

use std::sync::Arc;

const DNS_RECORD_DIR: &str = "dns_db";

const DNS_MAX_AGE: u64 = 7 * 86400;

#[derive(Clone, Debug)]
pub struct DNSResultRecord {
    pub domain: Domain,
    pub cnames: Vec<Domain>,
    pub ips: Vec<std::net::IpAddr>,
}

impl FromStr for DNSResultRecord {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split(';');
        let domain: Domain = parts.next().ok_or(())?.parse().map_err(|_| ())?;
        let mut cnames: Vec<Domain> = Vec::new();
        for cname in parts.next().ok_or(())?.split(',').filter(|c| !c.is_empty()) {
            cnames.push(cname.parse().map_err(|_| ())?)
        }
        let mut ips: Vec<std::net::IpAddr> = Vec::new();
        for ip in parts
            .next()
            .ok_or(())?
            .trim_end()
            .split(',')
            .filter(|c| !c.is_empty())
        {
            ips.push(ip.parse().map_err(|_| ())?)
        }
        Ok(DNSResultRecord {
            domain,
            cnames,
            ips,
        })
    }
}

impl std::fmt::Display for DNSResultRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut output = String::new();
        output.push_str(&self.domain);
        output.push(';');
        for cname in self.cnames.iter() {
            output.push_str(&cname);
            output.push(',');
        }
        output.push(';');
        for ip in self.ips.iter() {
            output.push_str(&ip.to_string());
            output.push(',');
        }
        write!(f, "{}", output)
    }
}

pub trait DomainRecordHandler: Send + Sync + Clone {
    fn handle_domain_record(&self, record: &DNSResultRecord);
}

#[derive(Clone)]
struct DNSDBReader<T: DomainRecordHandler> {
    domains: DomainSetShardedDefault,
    record_handler: T,
}

impl<T: DomainRecordHandler> DNSDBReader<T> {
    fn new(record_handler: T, domains: DomainSetShardedDefault) -> Self {
        DNSDBReader {
            domains,
            record_handler,
        }
    }
}

impl<T: DomainRecordHandler> DBReadHandler for DNSDBReader<T> {
    fn handle_input(&self, data: &str) {
        if let Ok(record) = data.parse::<DNSResultRecord>() {
            self.domains.remove_str(&record.domain);
            self.record_handler.handle_domain_record(&record)
        }
    }
}

async fn get_dns_results<T: 'static + DomainRecordHandler>(
    dns_record_handler: T,
    client: reqwest::Client,
    server: Arc<String>,
    domain: Domain,
) -> Option<DNSResultRecord> {
    tokio::spawn(async move {
        let result = doh::lookup_domain(server, client, 1, &domain).await.ok()?;
        if let Some(record) = &result {
            dns_record_handler.handle_domain_record(&record);
        }
        Some(result.unwrap_or_else(|| DNSResultRecord {
            domain,
            cnames: Vec::new(),
            ips: Vec::new(),
        }))
    })
    .await
    .ok()?
}

pub async fn lookup_domains<T: 'static + DomainRecordHandler>(
    domains: DomainSetShardedDefault,
    dns_record_handler: T,
    servers: &[Arc<String>],
    client: &reqwest::Client,
) -> Result<(), Box<dyn std::error::Error>> {
    let db_record_handler = DNSDBReader::new(dns_record_handler.clone(), domains.clone());
    let mut db = DirectoryDB::new(&std::path::Path::new(DNS_RECORD_DIR), DNS_MAX_AGE).await?;
    db.read(db_record_handler).await?;

    println!("Looking up {} domains", domains.len());
    if domains.is_empty() {
        return Ok(());
    }
    let total_length = domains.len();
    let mut domain_iter = domains.into_iter_domains();
    let mut tasks = futures::stream::FuturesUnordered::new();
    for (i, domain) in (0..100).zip(&mut domain_iter) {
        tasks.push(get_dns_results(
            dns_record_handler.clone(),
            client.clone(),
            servers[i % servers.len()].clone(),
            domain,
        ));
    }
    println!("Created initial tasks");
    let now = std::time::Instant::now();
    let mut i: usize = 0;
    let mut error_count: usize = 0;
    let display_status = |i: usize, error_count: usize, now: &std::time::Instant| {
        println!(
            "{}/{} {}/s with {} errors",
            i,
            total_length,
            i as f32 / now.elapsed().as_secs_f32(),
            error_count,
        )
    };
    while let Some(record) = tasks.next().await {
        if let Some(record) = record {
            if i % 1000 == 0 {
                display_status(i, error_count, &now);
            }
            db.write_line(record.to_string().as_bytes()).await?;
        } else {
            error_count += 1;
        }
        if let Some(next_domain) = domain_iter.next() {
            tasks.push(get_dns_results(
                dns_record_handler.clone(),
                client.clone(),
                servers[i % servers.len()].clone(),
                next_domain,
            ));
        }
        i += 1;
    }
    db.flush().await?;
    display_status(i, error_count, &now);
    Ok(())
}
