use serde::Deserialize;

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

#[derive(Debug, Default)]
pub struct DNSLookupResults {
    pub ip_addresses: Vec<std::net::IpAddr>,
    pub cnames: Vec<String>,
}

async fn lookup_domain_(
    server: &str,
    client: &reqwest::Client,
    domain: &str,
) -> Result<Option<DNSLookupResults>, reqwest::Error> {
    let json: DoHResult = client
        .get(server)
        .query(&[("name", domain), ("type", "1")])
        .send()
        .await?
        .json()
        .await?;
    if json.Status == 0 {
        let mut result = DNSLookupResults::default();
        for answer in json.Answer.iter() {
            match answer.r#type {
                1 => {
                    if let Ok(ip_addr) = answer.data.parse() {
                        result.ip_addresses.push(ip_addr);
                    } else {
                        println!("Failed with IP: {}", answer.data);
                    }
                }
                5 => result.cnames.push(answer.data.clone()),
                n => println!("Unknown DNS Record Type: {}", n),
            }
        }
        Ok(Some(result))
    } else {
        Ok(None)
    }
}
pub async fn lookup_domain(
    server: &str,
    client: &reqwest::Client,
    attempts: usize,
    domain: &str,
) -> Option<DNSLookupResults> {
    for _ in 0..attempts {
        if let Ok(result) = lookup_domain_(server, client, domain).await {
            return result;
        }
    }
    None
}
