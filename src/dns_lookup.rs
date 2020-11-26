use std::str::FromStr;

use tokio::stream::StreamExt;

use crate::{doh, DirectoryDB, Domain};

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

async fn get_dns_results(
    client: &reqwest::Client,
    server: &str,
    domain: Domain,
) -> Result<DNSResultRecord, Box<dyn std::error::Error>> {
    Ok(doh::lookup_domain(&server, &client, 3, &domain)
        .await?
        .unwrap_or_else(|| DNSResultRecord {
            domain,
            cnames: Vec::new(),
            ips: Vec::new(),
        }))
}

pub async fn lookup_domains<F>(
    mut domains: std::collections::HashSet<Domain>,
    mut f: F,

    servers: &[String],
    client: &reqwest::Client,
) -> Result<(), Box<dyn std::error::Error>>
where
    F: FnMut(&Domain, &[Domain], &[std::net::IpAddr]),
{
    let mut db = DirectoryDB::new(&std::path::Path::new(DNS_RECORD_DIR), DNS_MAX_AGE).await?;
    db.read(|line| {
        if let Ok(record) = line.parse::<DNSResultRecord>() {
            domains.remove(&record.domain);
            f(&record.domain, &record.cnames, &record.ips)
        }
    })
    .await?;

    println!("Looking up {} domains", domains.len());
    if domains.is_empty() {
        return Ok(());
    }
    let total_length = domains.len();
    let mut domain_iter = domains.drain();
    let mut tasks = futures::stream::FuturesUnordered::new();
    for (i, domain) in (0..500).zip(&mut domain_iter) {
        tasks.push(get_dns_results(
            &client,
            &servers[i % servers.len()],
            domain,
        ));
    }
    println!("Created initial tasks");
    println!("Stack left: {:?}", stacker::remaining_stack());
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
        if let Ok(record) = record {
            if i % 1000 == 0 {
                display_status(i, error_count, &now);
            }
            f(&record.domain, &record.cnames, &record.ips);
            db.write_line(record.to_string().as_bytes()).await?;
        } else {
            error_count += 1;
        }
        if let Some(next_domain) = domain_iter.next() {
            tasks.push(get_dns_results(
                &client,
                &servers[i % servers.len()],
                next_domain,
            ));
        }
        i += 1;
    }
    db.flush().await?;
    display_status(i, error_count, &now);
    Ok(())
}
