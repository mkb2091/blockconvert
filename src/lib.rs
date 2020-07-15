#[macro_use]
extern crate lazy_static;

pub mod doh;
pub mod domain_filter;
pub mod list_downloader;
pub mod validator;

use validator::Domain;

use serde::*;

use async_std::io::BufWriter;
use async_std::prelude::*;

lazy_static! {
    static ref DOMAIN_REGEX: regex::Regex = regex::Regex::new("...").unwrap();
}

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

pub struct BlockConvert {
    filter: domain_filter::DomainFilter,
    blocked_domains: std::collections::HashSet<Domain>,
    allowed_domains: std::collections::HashSet<Domain>,
    blocked_ip_addrs: std::collections::HashSet<std::net::IpAddr>,
    allowed_ip_addrs: std::collections::HashSet<std::net::IpAddr>,
}

impl BlockConvert {
    pub fn from(filter_lists: &[(FilterListType, String)]) -> Self {
        let mut builder = domain_filter::DomainFilterBuilder::new();
        let mut extracted_domains: std::collections::HashSet<String> = Default::default();
        let mut blocked_domains: std::collections::HashSet<Domain> = Default::default();
        let mut allowed_domains: std::collections::HashSet<Domain> = Default::default();
        let mut blocked_ip_addrs: std::collections::HashSet<std::net::IpAddr> = Default::default();
        let mut allowed_ip_addrs: std::collections::HashSet<std::net::IpAddr> = Default::default();
        for (list_type, data) in filter_lists.iter() {
            for domain in DOMAIN_REGEX.find_iter(data) {
                extracted_domains.insert(domain.as_str().to_string());
            }
            if *list_type != FilterListType::PrivacyBadger {
                for line in data.lines() {
                    match list_type {
                        FilterListType::Adblock => builder.add_adblock_rule(line),
                        FilterListType::RegexAllowlist => builder.add_allow_regex(line),
                        FilterListType::RegexBlocklist => builder.add_disallow_regex(line),
                        FilterListType::DomainBlocklist => {
                            if let Some(domain) = line
                                .split_whitespace()
                                .next()
                                .and_then(|domain| domain.split_terminator('#').next())
                                .and_then(|domain| domain.parse::<Domain>().ok())
                            {
                                blocked_domains.insert(domain);
                            }
                        }
                        FilterListType::DomainAllowlist => {
                            if let Some(domain) = line
                                .split_whitespace()
                                .next()
                                .and_then(|domain| domain.split_terminator('#').next())
                                .and_then(|domain| domain.parse::<Domain>().ok())
                            {
                                allowed_domains.insert(domain);
                            }
                        }
                        FilterListType::IPBlocklist => {
                            if let Some(ip) = line
                                .split_whitespace()
                                .next()
                                .and_then(|ip| ip.split_terminator('#').next())
                                .and_then(|ip| ip.parse::<std::net::IpAddr>().ok())
                            {
                                blocked_ip_addrs.insert(ip);
                            }
                        }
                        FilterListType::IPAllowlist => {
                            if let Some(ip) = line
                                .split_whitespace()
                                .next()
                                .and_then(|ip| ip.split_terminator('#').next())
                                .and_then(|ip| ip.parse::<std::net::IpAddr>().ok())
                            {
                                allowed_ip_addrs.insert(ip);
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
                                    if let Some(second_part) = parts
                                        .next()
                                        .and_then(|domain| domain.split_terminator('#').next())
                                    {
                                        if second_part.starts_with("*.") {
                                            builder.add_disallow_subdomain(second_part)
                                        } else if let Ok(domain) = second_part.parse::<Domain>() {
                                            blocked_domains.insert(domain);
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
        let mut generated = Self {
            filter: builder.to_domain_filter(),
            blocked_domains,
            allowed_domains,
            blocked_ip_addrs,
            allowed_ip_addrs,
        };
        generated.remove_allowed_from_blocked();
        generated.apply_filter_to_domains(extracted_domains.iter());
        generated
    }

    fn remove_allowed_from_blocked(&mut self) {
        self.blocked_domains = self
            .blocked_domains
            .difference(&self.allowed_domains)
            .filter(|domain| self.filter.allowed(domain).unwrap_or(false) == false)
            .cloned()
            .collect();

        self.blocked_ip_addrs = self
            .blocked_ip_addrs
            .difference(&self.allowed_ip_addrs)
            .filter(|ip| self.filter.allowed(&ip.to_string()).unwrap_or(false) == false)
            .cloned()
            .collect();
    }

    pub fn apply_filter_to_domains<'a, T>(&mut self, domains: T)
    where
        T: Iterator<Item = &'a String>,
    {
        for domain in domains.filter_map(|domain| domain.parse::<Domain>().ok()) {
            if let Some(allowed) = self.filter.allowed(&domain) {
                if allowed {
                    self.blocked_domains.remove(&domain);
                    self.allowed_domains.insert(domain.clone());
                } else {
                    self.blocked_domains.insert(domain.clone());
                }
            }
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
