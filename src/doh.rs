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

#[derive(Debug)]
pub enum LookupError {
    Request(reqwest::Error),
    Parsing(serde_json::Error),
}

impl From<reqwest::Error> for LookupError {
    fn from(error: reqwest::Error) -> Self {
        Self::Request(error)
    }
}

impl From<serde_json::Error> for LookupError {
    fn from(error: serde_json::Error) -> Self {
        Self::Parsing(error)
    }
}

impl std::fmt::Display for LookupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Request(io) => write!(f, "DOH Request Error: {}", io),
            Self::Parsing(parsing) => write!(f, "DOH Parsing Error: {}", parsing),
        }
    }
}

impl std::error::Error for LookupError {}

async fn lookup_domain_(
    server: Arc<str>,
    client: &reqwest::Client,
    timeout: Option<std::time::Duration>,
    domain: &Domain,
) -> Result<Option<DNSResultRecord>, LookupError> {
    let mut req = client
        .get(&*server)
        .query(&[("name", &**domain), ("type", "1")]);
    if let Some(timeout) = timeout {
        req = req.timeout(timeout);
    }

    let data = req
        .send()
        .await
        .map_err(|err| {
            println!("Error: {:?}", err);
            err
        })?
        .text()
        .await
        .map_err(|err| {
            println!("Error: {:?}", err);
            err
        })?;
    let json: DoHResult = serde_json::from_str(&data).map_err(|error| {
        println!("Error: {:?}\nWith data:  {:?}", error, data);
        error
    })?;
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
    server: Arc<str>,
    client: reqwest::Client,
    attempts: usize,
    timeout: Option<std::time::Duration>,
    domain: &Domain,
) -> Result<Option<DNSResultRecord>, LookupError> {
    for _ in 0..attempts {
        if let Ok(result) = lookup_domain_(server.clone(), &client, timeout, domain).await {
            return Ok(result);
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
    lookup_domain_(server, &client, timeout, domain).await
}
