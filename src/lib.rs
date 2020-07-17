#[macro_use]
extern crate lazy_static;

pub mod dns_lookup;
pub mod doh;
pub mod domain_filter;
pub mod list_downloader;
pub mod validator;

use validator::Domain;

use serde::*;

use async_std::io::BufWriter;
use async_std::prelude::*;

lazy_static! {
    static ref DOMAIN_REGEX: regex::Regex =
        regex::Regex::new("(?:[0-9A-Za-z-]+[.])+[0-9A-Za-z-]+").unwrap();
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, PartialOrd, Eq, Ord)]
pub struct FilterListRecord {
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

pub struct BlockConvert {
    filter: domain_filter::DomainFilter,
    blocked_domains: std::collections::HashSet<Domain>,
    allowed_domains: std::collections::HashSet<Domain>,
    blocked_ip_addrs: std::collections::HashSet<std::net::IpAddr>,
    allowed_ip_addrs: std::collections::HashSet<std::net::IpAddr>,
    extracted_domains: std::collections::HashSet<Domain>,
}

impl BlockConvert {
    pub fn from(filter_lists: &[(FilterListType, String)]) -> Self {
        let mut builder = domain_filter::DomainFilterBuilder::new();
        let mut extracted_domains: std::collections::HashSet<Domain> = Default::default();
        for (list_type, data) in filter_lists.iter() {
            for domain in DOMAIN_REGEX
                .find_iter(data)
                .filter_map(|domain| domain.as_str().parse::<Domain>().ok())
            {
                extracted_domains.insert(domain);
            }
            if *list_type != FilterListType::PrivacyBadger {
                for line in data.lines() {
                    match list_type {
                        FilterListType::Adblock => builder.add_adblock_rule(line),
                        FilterListType::RegexAllowlist => builder.add_allow_regex(line),
                        FilterListType::RegexBlocklist => builder.add_disallow_regex(line),
                        FilterListType::DomainBlocklist => {
                            if let Some((domain, is_star_subdomain)) = line
                                .split_whitespace()
                                .next()
                                .and_then(|domain| domain.split_terminator('#').next())
                                .and_then(|unprocessed| {
                                    unprocessed
                                        .trim_start_matches("*.")
                                        .parse::<Domain>()
                                        .ok()
                                        .map(|domain| (domain, unprocessed.starts_with("*.")))
                                })
                            {
                                extracted_domains.insert(domain.clone());
                                if is_star_subdomain {
                                    builder.add_disallow_subdomain(domain)
                                } else {
                                    builder.add_disallow_domain(domain);
                                }
                            }
                        }
                        FilterListType::DomainAllowlist => {
                            if let Some((domain, is_star_subdomain)) = line
                                .split_whitespace()
                                .next()
                                .and_then(|domain| domain.split_terminator('#').next())
                                .and_then(|unprocessed| {
                                    unprocessed
                                        .trim_start_matches("*.")
                                        .parse::<Domain>()
                                        .ok()
                                        .map(|domain| (domain, unprocessed.starts_with("*.")))
                                })
                            {
                                extracted_domains.insert(domain.clone());
                                if is_star_subdomain {
                                    builder.add_allow_subdomain(domain)
                                } else {
                                    builder.add_allow_domain(domain);
                                }
                            }
                        }
                        FilterListType::IPBlocklist => {
                            if let Some(ip) = line
                                .split_whitespace()
                                .next()
                                .and_then(|ip| ip.split_terminator('#').next())
                                .and_then(|ip| ip.parse::<std::net::IpAddr>().ok())
                            {
                                builder.add_disallow_ip_addr(ip);
                            }
                        }
                        FilterListType::IPAllowlist => {
                            if let Some(ip) = line
                                .split_whitespace()
                                .next()
                                .and_then(|ip| ip.split_terminator('#').next())
                                .and_then(|ip| ip.parse::<std::net::IpAddr>().ok())
                            {
                                builder.add_allow_ip_addr(ip);
                            }
                        }
                        FilterListType::Hostfile => {
                            let mut parts = line.split_whitespace();
                            if let Some(ip) = parts.next() {
                                if match ip {
                                    "0.0.0.0" => true,
                                    "127.0.0.1" => true,
                                    "::1" => true,
                                    _ => false,
                                } {
                                    if let Some((domain, is_star_subdomain)) = parts
                                        .next()
                                        .and_then(|domain| domain.split_terminator('#').next())
                                        .and_then(|unprocessed| {
                                            unprocessed
                                                .trim_start_matches("*.")
                                                .parse::<Domain>()
                                                .ok()
                                                .map(|domain| {
                                                    (domain, unprocessed.starts_with("*."))
                                                })
                                        })
                                    {
                                        extracted_domains.insert(domain.clone());
                                        if is_star_subdomain {
                                            builder.add_disallow_subdomain(domain)
                                        } else {
                                            builder.add_disallow_domain(domain);
                                        }
                                    }
                                }
                            }
                        }
                        FilterListType::DNSRPZ => {
                            println!("Currently DNSRPZ is not supported");
                            break;
                        }
                        _ => unimplemented!(),
                    }
                }
            }
        }
        Self {
            filter: builder.to_domain_filter(),
            blocked_domains: Default::default(),
            allowed_domains: Default::default(),
            blocked_ip_addrs: Default::default(),
            allowed_ip_addrs: Default::default(),
            extracted_domains,
        }
    }

    pub async fn check_dns(&mut self, servers: &[String], client: &reqwest::Client) {
        let mut extracted_domains = Default::default();
        std::mem::swap(&mut extracted_domains, &mut self.extracted_domains);
        let _ = dns_lookup::lookup_domains(
            extracted_domains,
            |domain, cnames, ips| self.process_domain(domain, cnames, ips),
            servers,
            client,
        )
        .await;
    }

    fn process_domain(&mut self, domain: &Domain, cnames: &[Domain], ips: &[std::net::IpAddr]) {
        if ips.is_empty() {
            return;
        }
        if let Some(allowed) = self.filter.allowed(domain, cnames, ips) {
            if allowed {
                self.allowed_domains.insert(domain.clone())
            } else {
                self.blocked_domains.insert(domain.clone())
            };
        }
    }

    pub async fn write_all(
        &self,
        blocked_domains: &std::path::Path,
        allowed_domains: &std::path::Path,
        blocked_ip_addrs: &std::path::Path,
        allowed_ip_addrs: &std::path::Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        async fn write_to_file<T: std::fmt::Display + Ord>(
            data: &std::collections::HashSet<T>,
            path: &std::path::Path,
        ) -> Result<(), Box<dyn std::error::Error>> {
            let file = async_std::fs::File::create(path).await?;
            let mut buf = BufWriter::new(file);
            let mut sorted: Vec<_> = data.iter().collect();
            sorted.sort_unstable();
            for item in sorted.iter() {
                buf.write_all(format!("{}\n", item).as_bytes()).await?;
            }
            Ok(())
        }

        futures::try_join!(
            write_to_file(&self.blocked_domains, blocked_domains),
            write_to_file(&self.allowed_domains, allowed_domains),
            write_to_file(&self.blocked_ip_addrs, blocked_ip_addrs),
            write_to_file(&self.allowed_ip_addrs, allowed_ip_addrs),
        )
        .map(|_| ())
    }
}
