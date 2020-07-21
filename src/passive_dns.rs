use crate::{get_blocked_ips_path, DirectoryDB, Domain, EXTRACTED_DOMAINS_DIR};

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

async fn get_ips() -> Result<std::collections::HashSet<std::net::IpAddr>, Box<dyn std::error::Error>>
{
    let mut file = async_std::fs::File::open(&get_blocked_ips_path()).await?;
    let mut text = String::new();
    file.read_to_string(&mut text).await?;
    Ok(text
        .lines()
        .filter_map(|line| line.parse::<std::net::IpAddr>().ok())
        .collect())
}

pub async fn argus_passive_dns() -> Result<(), Box<dyn std::error::Error>> {
    let mut ips = get_ips().await?;

    let mut path = std::path::PathBuf::from(PASSIVE_DNS_RECORD_DIR);
    path.push("argus");
    let mut db = DirectoryDB::new(&path).await?;
    db.read(|line| {
        if let Ok(ip) = line.trim().parse::<std::net::IpAddr>() {
            ips.remove(&ip);
        }
    })
    .await?;
    let total_length = ips.len();
    println!("Argus: {} ips remaining", total_length);
    let client = reqwest::Client::new();
    let mut ips_checked: u64 = 0;
    let mut domains_found: u64 = 0;
    let mut errors: u64 = 0;

    let _ = std::fs::create_dir(EXTRACTED_DOMAINS_DIR);
    let mut path = std::path::PathBuf::from(EXTRACTED_DOMAINS_DIR);
    path.push(std::path::PathBuf::from(format!(
        "argus_{:?}",
        chrono::Utc::today()
    )));
    let mut wtr = BufWriter::new(
        OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
            .await?,
    );
    let now = std::time::Instant::now();
    let mut last_flushed = std::time::Instant::now();
    for ip in ips.into_iter() {
        ips_checked += 1;
        if let Ok(response) = client
            .get(&format!(
                "https://api.mnemonic.no/pdns/v3/{}?limit=100000",
                ip
            ))
            .send()
            .await
        {
            if let Ok(json) = response.json::<serde_json::Value>().await {
                if json.pointer("/responseCode")
                    != Some(&serde_json::Value::Number(serde_json::Number::from(200)))
                {
                    println!(
                        "ARGUS: Non 200 response code: {:?}",
                        json.pointer("/responseCode")
                    );
                    return Err(Box::new(InvalidResponseCode::default()));
                }
                if let Some(data) = json.pointer("/data").and_then(|data| data.as_array()) {
                    for domain in data.iter().filter_map(|item| {
                        item.pointer("/query").and_then(|domain| domain.as_str())
                    }) {
                        if let Ok(domain) = domain.parse::<Domain>() {
                            domains_found += 1;
                            wtr.write_all(domain.to_string().as_bytes()).await?;
                            wtr.write_all(b"\n").await?;
                        } else {
                            println!("ARGUS: Failed to parse: {}", domain)
                        }
                    }
                } else {
                    println!("No data field: {:?}", json);
                    errors += 1;
                }
            } else {
                println!("ARGUS: Failed to parse as json");
                errors += 1;
            }
        } else {
            println!("ARGUS: Connection failed");
            errors += 1;
            async_std::task::sleep(std::time::Duration::from_secs(15_u64)).await
        }
        async_std::task::sleep(std::time::Duration::from_secs(1_u64)).await;
        db.write_line(ip.to_string().as_bytes()).await?;
        if last_flushed.elapsed().as_secs() > 10 {
            db.flush().await?;
            wtr.flush().await?;
            last_flushed = std::time::Instant::now();
            println!(
                "ARGUS: Checked {}/{} ips ({}/s), found {} domains with {} errors",
                ips_checked,
                total_length,
                (ips_checked as f32 / now.elapsed().as_secs_f32()),
                domains_found,
                errors
            );
        }
    }
    db.flush().await?;
    wtr.flush().await?;
    Ok(())
}

pub async fn threatminer_passive_dns() -> Result<(), Box<dyn std::error::Error>> {
    let mut ips = get_ips().await?;

    let mut path = std::path::PathBuf::from(PASSIVE_DNS_RECORD_DIR);
    path.push("threatminer");
    let mut db = DirectoryDB::new(&path).await?;
    db.read(|line| {
        if let Ok(ip) = line.trim().parse::<std::net::IpAddr>() {
            ips.remove(&ip);
        }
    })
    .await?;
    let total_length = ips.len();
    println!("THREATMINER: {} ips remaining", total_length);
    let client = reqwest::Client::new();
    let mut ips_checked: u64 = 0;
    let mut domains_found: u64 = 0;
    let mut errors: u64 = 0;

    let _ = std::fs::create_dir(EXTRACTED_DOMAINS_DIR);
    let mut path = std::path::PathBuf::from(EXTRACTED_DOMAINS_DIR);
    path.push(std::path::PathBuf::from(format!(
        "threatminer_{:?}",
        chrono::Utc::today()
    )));
    let mut wtr = BufWriter::new(
        OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
            .await?,
    );
    let now = std::time::Instant::now();
    let mut last_flushed = std::time::Instant::now();
    for ip in ips.into_iter() {
        ips_checked += 1;
        if let Ok(response) = client
            .get(&format!(
                "https://api.threatminer.org/v2/host.php?q={}&rt=2",
                ip
            ))
            .send()
            .await
        {
            if let Ok(json) = response.json::<serde_json::Value>().await {
                if json.pointer("/status_code")
                    != Some(&serde_json::Value::String("200".to_string()))
                    && json.pointer("/status_code")
                        != Some(&serde_json::Value::String("404".to_string()))
                {
                    println!(
                        "THREATMINER: Non 200 response code: {:?}",
                        json.pointer("/status_code")
                    );
                    return Err(Box::new(InvalidResponseCode::default()));
                }
                if let Some(data) = json.pointer("/results").and_then(|data| data.as_array()) {
                    for domain in data.iter().filter_map(|item| {
                        item.pointer("/domain").and_then(|domain| domain.as_str())
                    }) {
                        if let Ok(domain) = domain.parse::<Domain>() {
                            domains_found += 1;
                            wtr.write_all(domain.to_string().as_bytes()).await?;
                            wtr.write_all(b"\n").await?;
                        } else {
                            println!("THREATMINER: Failed to parse: {}", domain)
                        }
                    }
                } else {
                    println!("THREATMINER: No data field: {:?}", json);
                    errors += 1;
                }
            } else {
                println!("THREATMINER: Failed to parse as json");
                errors += 1;
            }
        } else {
            println!("THREATMINER: Connection failed");
            errors += 1;
            async_std::task::sleep(std::time::Duration::from_secs(15_u64)).await
        }
        async_std::task::sleep(std::time::Duration::from_secs(6_u64)).await;
        db.write_line(ip.to_string().as_bytes()).await?;
        if last_flushed.elapsed().as_secs() > 10 {
            db.flush().await?;
            wtr.flush().await?;
            last_flushed = std::time::Instant::now();
            println!(
                "THREATMINER: Checked {}/{} ips ({}/s), found {} domains with {} errors",
                ips_checked,
                total_length,
                (ips_checked as f32 / now.elapsed().as_secs_f32()),
                domains_found,
                errors
            );
        }
    }
    db.flush().await?;
    wtr.flush().await?;
    Ok(())
}

pub async fn virus_total_passive_dns(key: String) -> Result<(), Box<dyn std::error::Error>> {
    let mut ips = get_ips().await?;

    let mut path = std::path::PathBuf::from(PASSIVE_DNS_RECORD_DIR);
    path.push("virustotal");
    let mut db = DirectoryDB::new(&path).await?;
    db.read(|line| {
        if let Ok(ip) = line.trim().parse::<std::net::IpAddr>() {
            ips.remove(&ip);
        }
    })
    .await?;
    let total_length = ips.len();
    println!("VIRUSTOTAL: {} ips remaining", total_length);
    let client = reqwest::Client::new();
    let mut ips_checked: u64 = 0;
    let mut domains_found: u64 = 0;
    let mut errors: u64 = 0;

    let _ = std::fs::create_dir(EXTRACTED_DOMAINS_DIR);
    let mut path = std::path::PathBuf::from(EXTRACTED_DOMAINS_DIR);
    path.push(std::path::PathBuf::from(format!(
        "virustotal_{:?}",
        chrono::Utc::today()
    )));
    let mut wtr = BufWriter::new(
        OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
            .await?,
    );
    let now = std::time::Instant::now();
    let mut last_flushed = std::time::Instant::now();
    for ip in ips.into_iter() {
        ips_checked += 1;
        if let Ok(response) = client
            .get("https://www.virustotal.com/vtapi/v2/ip-address/report")
            .query(&[("apikey", &key), ("ip", &ip.to_string())])
            .send()
            .await
        {
            /*println!("response: {:?}", response.text().await?);
            loop {};*/
            if let Ok(json) = response.json::<serde_json::Value>().await {
                if json.pointer("/response_code")
                    != Some(&serde_json::Value::Number(serde_json::Number::from(1)))
                {
                    println!(
                        "VIRUSTOTAL: Non 1 response code: {:?}",
                        json.pointer("/status_code")
                    );
                    return Err(Box::new(InvalidResponseCode::default()));
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
                            wtr.write_all(domain.to_string().as_bytes()).await?;
                            wtr.write_all(b"\n").await?;
                        } else {
                            println!("VIRUSTOTAL: Failed to parse: {}", domain)
                        }
                    }
                } else {
                    println!("VIRUSTOTAL: No data field: {:?}", json);
                    errors += 1;
                }
            } else {
                println!("VIRUSTOTAL: Failed to parse as json");
                errors += 1;
            }
        } else {
            println!("VIRUSTOTAL: Connection failed");
            errors += 1;
            async_std::task::sleep(std::time::Duration::from_secs(15_u64)).await
        }
        async_std::task::sleep(std::time::Duration::from_secs(15_u64)).await;

        db.write_line(ip.to_string().as_bytes()).await?;
        if last_flushed.elapsed().as_secs() > 10 {
            db.flush().await?;
            wtr.flush().await?;
            last_flushed = std::time::Instant::now();
            println!(
                "VIRUSTOTAL: Checked {}/{} ips ({}/s), found {} domains with {} errors",
                ips_checked,
                total_length,
                (ips_checked as f32 / now.elapsed().as_secs_f32()),
                domains_found,
                errors
            );
        }
    }
    db.flush().await?;
    wtr.flush().await?;
    Ok(())
}
