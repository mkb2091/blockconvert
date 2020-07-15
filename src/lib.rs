pub mod doh;
pub mod domain_filter;
pub mod list_downloader;

use serde::*;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, PartialOrd, Eq, Ord)]
pub struct Record {
    pub name: String,
    pub url: String,
    pub author: String,
    pub license: String,
    pub expires: u64,
    pub list_type: FilterListType,
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, PartialOrd, Eq, Ord)]
pub enum FilterListType {
    Adblock,
    DomainBlocklist,
    DomainAllowlist,
    IPBlocklist,
    IPAllowlist,
    RegexAllowlist,
    RegexBlocklist,
    Hostfile,
    DNSRPZ,
    PrivacyBadger,
}

fn parse_file(data: &str, list_type: FilterListType) -> Vec<String> {
    let mut output: Vec<String> = Vec::new();
    if list_type != FilterListType::PrivacyBadger {
        for line in data.lines() {
            match list_type {
                FilterListType::Hostfile => {
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
                FilterListType::DNSRPZ => {}
                _ => output.push(line.trim().to_string()), // All other list types don't need the data to be extracted
            }
        }
    }
    output
}
