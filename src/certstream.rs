use crate::{Domain, EXTRACTED_DOMAINS_DIR};

use futures::SinkExt;
use futures::StreamExt;
use tokio::fs::OpenOptions;
use tokio::io::BufWriter;

use tokio::io::AsyncWriteExt;

const URL: &str = "wss://certstream.calidog.io/domains-only";

const KEEPALIVE_INTERVAL: u64 = 20;

pub async fn certstream() -> Result<(), Box<dyn std::error::Error>> {
    let _ = std::fs::create_dir(EXTRACTED_DOMAINS_DIR);
    let mut path = std::path::PathBuf::from(EXTRACTED_DOMAINS_DIR);
    path.push(std::path::PathBuf::from(format!(
        "certstream_{}",
        chrono::Utc::now().format("%Y-%m-%d %H-%M-%S")
    )));
    let mut wtr = BufWriter::new(
        OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
            .await?,
    );
    let mut counter: u64 = 0;
    let start = std::time::Instant::now();
    let mut last_output = std::time::Instant::now();
    let mut last_keepalive = std::time::Instant::now();
    loop {
        let (mut ws_stream, _response) = tokio_tungstenite::connect_async(URL).await?;
        while let Some(Ok(next)) = ws_stream.next().await {
            if let tokio_tungstenite::tungstenite::protocol::Message::Text(data) = next {
                match serde_json::from_str::<serde_json::Value>(&data) {
                    Ok(decoded) => {
                        if let Some(all_domains) =
                            decoded.pointer("/data").and_then(|data| data.as_array())
                        {
                            for domain in all_domains
                                .iter()
                                .filter_map(|domain| domain.as_str())
                                .filter_map(|domain| domain.parse::<Domain>().ok())
                            {
                                if last_output.elapsed().as_secs_f32() > 5.0 {
                                    println!(
                                        "Found {} domains ({}/s) via CertStream. Current domain: {}",
                                        counter, (counter as f32 / start.elapsed().as_secs_f32()), domain
                                    );
                                    last_output = std::time::Instant::now();
                                }
                                counter += 1;
                                wtr.write_all(domain.as_bytes()).await?;
                                wtr.write_all(b"\n").await?;
                            }
                        } else {
                            println!("Failed to extract `all_domain`");
                        }
                    }
                    Err(error) => {
                        println!("Error: {:?}", error);
                        println!("Failed to decode: {:?}\n", data);
                    }
                }
            } else {
                println!("Unknown type: {:?}", next)
            }
            if last_keepalive.elapsed().as_secs() > KEEPALIVE_INTERVAL {
                if let Err(error) = ws_stream
                    .send(tokio_tungstenite::tungstenite::protocol::Message::Text(
                        String::new(),
                    ))
                    .await
                {
                    println!("Failed to send keepalive: {:?}", error);
                }
                last_keepalive = std::time::Instant::now();
            }
        }
        println!("CertStream connection ended");
    }
}
