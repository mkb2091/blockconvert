use crate::dns_lookup::DNSResultRecord;
use crate::Domain;

use serde::Deserialize;

use std::sync::Arc;

#[derive(Deserialize, Debug)]
struct Question {
    name: String,
    r#type: usize,
}

#[derive(Deserialize, Debug)]
struct Answer {
    name: String,
    r#type: usize,
    #[serde(default)]
    ttl: usize,
    data: String,
}

#[allow(non_snake_case)]
#[derive(Deserialize, Debug)]
struct DoHResult {
    Status: usize,
    #[serde(default)]
    tc: bool,
    #[serde(default)]
    rd: bool,
    #[serde(default)]
    ad: bool,
    #[serde(default)]
    cd: bool,
    Question: Vec<Question>,
    #[serde(default)]
    Answer: Vec<Answer>,
    #[serde(default)]
    additional: Vec<()>,
    #[serde(default)]
    comment: String,
}

async fn lookup_domain_(
    server: Arc<String>,
    client: &reqwest::Client,
    domain: &Domain,
) -> Result<Option<DNSResultRecord>, reqwest::Error> {
    let json: DoHResult = client
        .get(&*server)
        .query(&[("name", &**domain), ("type", "1")])
        .send()
        .await?
        .json()
        .await?;
    if json.Status == 0 {
        let mut result = DNSResultRecord {
            domain: domain.clone(),
            cnames: Vec::new(),
            ips: Vec::new(),
        };
        for answer in json.Answer.into_iter() {
            match answer.r#type {
                1 => {
                    if let Ok(ip_addr) = answer.data.parse() {
                        result.ips.push(ip_addr);
                    } else {
                        println!("Failed with IP: {}", answer.data);
                    }
                }
                5 | 39 => {
                    if let Ok(cname) = answer.data.trim_end_matches('.').parse::<Domain>() {
                        result.cnames.push(cname)
                    } else {
                        println!("Failed to parse: {} as domain", answer.data)
                    }
                }
                n => println!("Unexpected DNS record type: {}", n),
            }
        }
        Ok(Some(result))
    } else {
        Ok(None)
    }
}
pub async fn lookup_domain(
    server: Arc<String>,
    client: reqwest::Client,
    attempts: usize,
    domain: &Domain,
) -> Result<Option<DNSResultRecord>, reqwest::Error> {
    for _ in 0..attempts {
        if let Ok(result) = lookup_domain_(server.clone(), &client, domain).await {
            return Ok(result);
        }
    }
    lookup_domain_(server, &client, domain).await
}
