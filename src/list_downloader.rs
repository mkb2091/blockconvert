use std::io::BufRead;

#[derive(PartialEq, Eq)]
pub enum FilterListTypes {
    Regex,
    PlainDomain,
    DomainWithStar,
    HostFile,
    ExtractFromUrl,
    DNSRPZ,
    Adblock,
    PrivacyBadger,
}

fn parse_file(data: &mut dyn std::io::Read, list_type: FilterListTypes) -> Vec<String> {
    let mut data = std::io::BufReader::new(data);
    let mut output: Vec<String> = Vec::new();
    if list_type != FilterListTypes::PrivacyBadger {
        let mut line = String::new();
        while let Ok(result) = data.read_line(&mut line) {
            if result == 0 {
                break;
            }
            match list_type {
                FilterListTypes::HostFile => {
                    let mut parts = line.split_whitespace();
                    if let Some(ip) = parts.next() {
                        if match ip {
                            "0.0.0.0" => true,
                            "127.0.0.1" => true,
                            "::1" => true,
                            _ => false,
                        } {
                            if let Some(second_part) = parts
                                .next()
                                .and_then(|domain| domain.split_terminator('#').next())
                            {
                                output.push(second_part.to_string());
                            }
                        }
                    }
                }
                FilterListTypes::ExtractFromUrl => {}
                FilterListTypes::DNSRPZ => {}
                _ => output.push(line.trim().to_string()), // All other list types don't need the data to be extracted
            }
        }
    }
    output
}

async fn download_list(client: &reqwest::Client, url: &str) -> Result<Vec<String>, reqwest::Error> {
    let text = client.get(url).send().await?.text().await?;
    Ok(vec![])
}

pub async fn download_list_if_expired(
    client: &reqwest::Client,
    url: &str,
    expires: usize,
    list_type: FilterListTypes,
) -> Vec<String> {
    Vec::new()
}
