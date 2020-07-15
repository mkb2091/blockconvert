use serde::*;

const LIST_CSV: &'static str = "filterlists.csv";

#[derive(Debug, Serialize, Deserialize, PartialEq, PartialOrd, Eq, Ord)]
struct Record {
    name: String,
    url: String,
    author: String,
    license: String,
    expires: usize,
    list_type: FilterListType,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, PartialOrd, Eq, Ord)]
enum FilterListType {
    Adblock,
    DomainBlocklist,
    DomainAllowlist,
    IPBlocklist,
    IPAllowlist,
    Hostfile,
    DNSRPZ,
    PrivacyBadger,
}

fn read_csv() -> Result<Vec<Record>, csv::Error> {
    let path = std::path::Path::new(LIST_CSV);
    let mut records: Vec<Record> = csv::Reader::from_path(path)?
        .deserialize()
        .map(|result| {
            let record: Record = result?;
            Ok(record)
        })
        .filter_map(|result: Result<Record, csv::Error>| result.ok())
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

fn main() {
    println!("Result: {:?}", read_csv());

    return;
    let mut rt = tokio::runtime::Runtime::new().unwrap();
    let mut client = reqwest::Client::new();
    let servers = [
        "https://dns.google.com/resolve".to_string(),
        "https://cloudflare-dns.com/dns-query".to_string(),
    ];
    let mut rng = rand::thread_rng();
    let attempts = 3;
    let dns_result = blockconvert::doh::lookup_domain(
        &servers,
        &mut client,
        &mut rng,
        attempts,
        "analytics.google.com",
    );
    let output = rt.block_on(dns_result);
    println!("Result: {:?}", output);
}
