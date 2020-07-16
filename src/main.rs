use blockconvert::FilterListRecord;

const LIST_CSV: &'static str = "filterlists.csv";

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

async fn generate() {
    let client = reqwest::Client::new();
    let servers = [
        "https://dns.google.com/resolve".to_string(),
        "https://cloudflare-dns.com/dns-query".to_string(),
    ];
    if let Ok(records) = read_csv() {
        let downloaded = blockconvert::list_downloader::download_all(&client, &records).await;
        let mut bc = blockconvert::BlockConvert::from(&downloaded);
        bc.check_dns(&servers, &client).await;
        let _ = bc
            .write_all(
                &std::path::Path::new("output/blocked_domains.txt"),
                &std::path::Path::new("output/allowed_domains.txt"),
                &std::path::Path::new("output/blocked_ips.txt"),
                &std::path::Path::new("output/allowed_ips.txt"),
            )
            .await;
    }
}

fn main() {
    let mut rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(generate());
}
