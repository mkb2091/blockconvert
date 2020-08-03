use crate::{DirectoryDB, Domain, EXTRACTED_DOMAINS_DIR, EXTRACTED_MAX_AGE};

use async_std::prelude::*;

use async_std::fs::OpenOptions;
use async_std::io::BufWriter;

const PASSIVE_DNS_RECORD_DIR: &str = "passive_dns_db";

#[derive(Default, Debug)]
pub struct InvalidResponseCode {}

impl std::error::Error for InvalidResponseCode {}

impl std::fmt::Display for InvalidResponseCode {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

struct PassiveDNS {
    ips: Vec<std::net::IpAddr>,
    db: DirectoryDB,
    wtr: BufWriter<async_std::fs::File>,
    sleep_time: f32,
    total_length: u64,
    last_flushed: std::time::Instant,
    last_fetched: std::time::Instant,
}

impl PassiveDNS {
    async fn new(
        mut ips: std::collections::HashSet<std::net::IpAddr>,
        name: &str,
        sleep_time: f32,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut path = std::path::PathBuf::from(PASSIVE_DNS_RECORD_DIR);
        path.push(name);
        let db = DirectoryDB::new(&path, EXTRACTED_MAX_AGE).await?;
        db.read(|line| {
            if let Ok(ip) = line.trim().parse::<std::net::IpAddr>() {
                ips.remove(&ip);
            }
        })
        .await?;
        let total_length = ips.len() as u64;

        let _ = std::fs::create_dir(EXTRACTED_DOMAINS_DIR);
        let mut path = std::path::PathBuf::from(EXTRACTED_DOMAINS_DIR);
        path.push(std::path::PathBuf::from(format!(
            "{}_{:?}",
            name,
            chrono::Utc::today()
        )));
        let wtr = BufWriter::new(
            OpenOptions::new()
                .append(true)
                .create(true)
                .open(path)
                .await?,
        );
        Ok(Self {
            ips: ips.into_iter().collect(),
            db,
            wtr,
            sleep_time,
            total_length,
            last_flushed: std::time::Instant::now(),
            last_fetched: std::time::Instant::now(),
        })
    }
    async fn flush(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.wtr.flush().await?;
        self.db.flush().await?;
        self.last_flushed = std::time::Instant::now();
        Ok(())
    }
    async fn check_flush(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.last_flushed.elapsed().as_secs() > 10 {
            self.flush().await?;
        }
        Ok(())
    }
    async fn next_ip(&mut self) -> Option<std::net::IpAddr> {
        let sleep_time = self.sleep_time - self.last_fetched.elapsed().as_secs_f32();
        if sleep_time > 0.0 {
            async_std::task::sleep(std::time::Duration::from_secs_f32(sleep_time)).await;
        }
        self.check_flush().await.ok()?;
        self.last_fetched = std::time::Instant::now();
        self.ips.pop()
    }
    async fn add_domain(&mut self, domain: &Domain) -> Result<(), Box<dyn std::error::Error>> {
        self.wtr.write_all(domain.to_string().as_bytes()).await?;
        self.wtr.write_all(b"\n").await?;
        self.check_flush().await?;
        Ok(())
    }
    async fn finished_ip(
        &mut self,
        ip: std::net::IpAddr,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.db.write_line(ip.to_string().as_bytes()).await?;
        self.check_flush().await?;
        Ok(())
    }
}

pub async fn argus(
    ips: std::collections::HashSet<std::net::IpAddr>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut pd = PassiveDNS::new(ips, "argus", 60.0 / 100.0).await?;
    // Unauthenticated users are limited to 100 requests per minute, and 1000 requests per day.

    let client = reqwest::Client::new();

    let mut ips_checked: u64 = 0;
    let mut domains_found: u64 = 0;
    let mut errors: u64 = 0;
    let mut errors_in_a_row: u64 = 0;
    let start = std::time::Instant::now();
    let mut last_output = std::time::Instant::now();
    while let Some(ip) = pd.next_ip().await {
        ips_checked += 1;
        let mut errored = false;
        if let Ok(text) = client
            .get(&format!(
                "https://api.mnemonic.no/pdns/v3/{}?limit=100000",
                ip
            ))
            .send()
            .await?
            .text()
            .await
        {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                if json.pointer("/responseCode")
                    != Some(&serde_json::Value::Number(serde_json::Number::from(200)))
                {
                    println!(
                        "ARGUS: Non 200 response code: {:?}",
                        json.pointer("/responseCode")
                    );
                    errored = true;
                }
                if let Some(data) = json.pointer("/data").and_then(|data| data.as_array()) {
                    for domain in data.iter().filter_map(|item| {
                        item.pointer("/query").and_then(|domain| domain.as_str())
                    }) {
                        if let Ok(domain) = domain.parse::<Domain>() {
                            domains_found += 1;
                            pd.add_domain(&domain).await?;
                        } else {
                            println!("ARGUS: Failed to parse: {}", domain)
                        }
                    }
                } else {
                    println!("No data field: {:?}", json);
                    errored = true;
                }
            } else {
                println!("ARGUS: Failed to parse as json: {}", text);
                errored = true;
            }
        } else {
            println!("ARGUS: Connection failed");
            errored = true;
            async_std::task::sleep(std::time::Duration::from_secs(15_u64)).await
        }
        if errored {
            errors += 1;
            errors_in_a_row += 1;
            if errors_in_a_row > 10 {
                println!("ARGUS: Exceeded max errors in a row");
                pd.flush().await?;
                return Err(Box::new(InvalidResponseCode::default()));
            }
        } else {
            errors_in_a_row = errors_in_a_row.saturating_sub(1);
            pd.finished_ip(ip).await?;
            if last_output.elapsed().as_secs() > 30 {
                last_output = std::time::Instant::now();
                println!(
                    "ARGUS: Checked {}/{} ips ({}/s), found {} domains with {} errors",
                    ips_checked,
                    pd.total_length,
                    (ips_checked as f32 / start.elapsed().as_secs_f32()),
                    domains_found,
                    errors
                );
            }
        }
    }
    println!(
        "ARGUS: Checked {}/{} ips ({}/s), found {} domains with {} errors",
        ips_checked,
        pd.total_length,
        (ips_checked as f32 / start.elapsed().as_secs_f32()),
        domains_found,
        errors
    );
    pd.flush().await?;
    Ok(())
}

pub async fn threatminer(
    ips: std::collections::HashSet<std::net::IpAddr>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut pd = PassiveDNS::new(ips, "threatminer", 6.0).await?;

    let client = reqwest::Client::new();

    let mut ips_checked: u64 = 0;
    let mut domains_found: u64 = 0;
    let mut errors: u64 = 0;
    let mut errors_in_a_row: u64 = 0;
    let start = std::time::Instant::now();
    let mut last_output = std::time::Instant::now();
    while let Some(ip) = pd.next_ip().await {
        ips_checked += 1;
        let mut errored = false;
        if let Ok(text) = client
            .get(&format!(
                "https://api.threatminer.org/v2/host.php?q={}&rt=2",
                ip
            ))
            .send()
            .await?
            .text()
            .await
        {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                if json.pointer("/status_code")
                    != Some(&serde_json::Value::String("200".to_string()))
                    && json.pointer("/status_code")
                        != Some(&serde_json::Value::String("404".to_string()))
                {
                    println!(
                        "THREATMINER: Non 200 response code: {:?}",
                        json.pointer("/status_code")
                    );
                    errored = true;
                }
                if let Some(data) = json.pointer("/results").and_then(|data| data.as_array()) {
                    for domain in data.iter().filter_map(|item| {
                        item.pointer("/domain").and_then(|domain| domain.as_str())
                    }) {
                        if let Ok(domain) = domain.parse::<Domain>() {
                            domains_found += 1;
                            pd.add_domain(&domain).await?;
                        } else {
                            println!("THREATMINER: Failed to parse: {}", domain)
                        }
                    }
                } else {
                    println!("THREATMINER: No data field: {:?}", json);
                    errored = true;
                }
            } else {
                println!("THREATMINER: Failed to parse as json: {}", text);
                errored = true;
            }
        } else {
            println!("THREATMINER: Connection failed");
            errored = true;
            async_std::task::sleep(std::time::Duration::from_secs(15_u64)).await
        }
        if errored {
            errors += 1;
            errors_in_a_row += 1;
            if errors_in_a_row > 10 {
                println!("THREATMINER: Exceeded max errors in a row");
                pd.flush().await?;
                return Err(Box::new(InvalidResponseCode::default()));
            }
        } else {
            errors_in_a_row = errors_in_a_row.saturating_sub(1);
            pd.finished_ip(ip).await?;
            if last_output.elapsed().as_secs() > 30 {
                last_output = std::time::Instant::now();
                println!(
                    "THREATMINER: Checked {}/{} ips ({}/s), found {} domains with {} errors",
                    ips_checked,
                    pd.total_length,
                    (ips_checked as f32 / start.elapsed().as_secs_f32()),
                    domains_found,
                    errors
                );
            }
        }
    }
    println!(
        "THREATMINER: Checked {}/{} ips ({}/s), found {} domains with {} errors",
        ips_checked,
        pd.total_length,
        (ips_checked as f32 / start.elapsed().as_secs_f32()),
        domains_found,
        errors
    );
    pd.flush().await?;
    Ok(())
}

pub async fn virus_total(
    ips: std::collections::HashSet<std::net::IpAddr>,
    key: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut pd = PassiveDNS::new(ips, "virustotal", 15.0).await?;

    let client = reqwest::Client::new();

    let mut ips_checked: u64 = 0;
    let mut domains_found: u64 = 0;
    let mut errors: u64 = 0;
    let mut errors_in_a_row: u64 = 0;
    let start = std::time::Instant::now();
    let mut last_output = std::time::Instant::now();
    while let Some(ip) = pd.next_ip().await {
        ips_checked += 1;
        let mut errored = false;
        if let Ok(text) = client
            .get("https://www.virustotal.com/vtapi/v2/ip-address/report")
            .query(&[("apikey", &key), ("ip", &ip.to_string())])
            .send()
            .await?
            .text()
            .await
        {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                if json.pointer("/response_code")
                    != Some(&serde_json::Value::Number(serde_json::Number::from(1)))
                {
                    println!(
                        "VIRUSTOTAL: Non 1 response code: {:?}",
                        json.pointer("/status_code")
                    );
                    errored = true;
                }
                if let Some(data) = json
                    .pointer("/resolutions")
                    .and_then(|data| data.as_array())
                {
                    for domain in data.iter().filter_map(|item| {
                        item.pointer("/hostname").and_then(|domain| domain.as_str())
                    }) {
                        if let Ok(domain) = domain.parse::<Domain>() {
                            domains_found += 1;
                            pd.add_domain(&domain).await?;
                        } else {
                            println!("VIRUSTOTAL: Failed to parse: {}", domain)
                        }
                    }
                } else {
                    println!("VIRUSTOTAL: No data field: {:?}", json);
                    errored = true;
                }
            } else {
                println!("VIRUSTOTAL: Failed to parse as json: {}", text);
                errored = true;
            }
        } else {
            println!("VIRUSTOTAL: Connection failed");
            errored = true;
            async_std::task::sleep(std::time::Duration::from_secs(15_u64)).await
        }
        if errored {
            errors += 1;
            errors_in_a_row += 1;
            if errors_in_a_row > 10 {
                println!("VIRUSTOTAL: Exceeded max errors in a row");
                pd.flush().await?;
                return Err(Box::new(InvalidResponseCode::default()));
            }
        } else {
            errors_in_a_row = errors_in_a_row.saturating_sub(1);
            pd.finished_ip(ip).await?;
            if last_output.elapsed().as_secs() > 30 {
                last_output = std::time::Instant::now();
                println!(
                    "VIRUSTOTAL: Checked {}/{} ips ({}/s), found {} domains with {} errors",
                    ips_checked,
                    pd.total_length,
                    (ips_checked as f32 / start.elapsed().as_secs_f32()),
                    domains_found,
                    errors
                );
            }
        }
    }
    println!(
        "VIRUSTOTAL: Checked {}/{} ips ({}/s), found {} domains with {} errors",
        ips_checked,
        pd.total_length,
        (ips_checked as f32 / start.elapsed().as_secs_f32()),
        domains_found,
        errors
    );
    pd.flush().await?;
    Ok(())
}
