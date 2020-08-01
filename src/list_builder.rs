use crate::{dns_lookup, Domain, FilterListType, DOMAIN_REGEX, IP_REGEX};

use async_std::io::BufWriter;
use async_std::prelude::*;

#[derive(Default)]
pub struct FilterListBuilder {
    filter_builder: blockconvert::DomainFilterBuilder,
    extracted_domains: std::collections::HashSet<Domain>,
    extracted_ips: std::collections::HashSet<std::net::IpAddr>,
}

impl FilterListBuilder {
    pub fn new() -> Self {
        Self::default()
    }
    fn add_domain_list(&mut self, data: &str, is_allow_list: bool) {
        for (domain, is_star_subdomain) in data
            .lines()
            .filter_map(|line| line.split_whitespace().next())
            .filter_map(|line| line.split_terminator('#').next())
            .filter_map(|unprocessed| {
                unprocessed
                    .trim_start_matches("*.")
                    .parse::<Domain>()
                    .ok()
                    .map(|domain| (domain, unprocessed.starts_with("*.")))
            })
        {
            match (is_allow_list, is_star_subdomain) {
                (true, true) => self.filter_builder.add_allow_subdomain(domain),
                (true, false) => self.filter_builder.add_allow_domain(domain),
                (false, true) => self.filter_builder.add_disallow_subdomain(domain),
                (false, false) => self.filter_builder.add_disallow_domain(domain),
            }
        }
    }

    pub fn add_list(&mut self, list_type: FilterListType, data: &str) {
        for domain in DOMAIN_REGEX
            .find_iter(data)
            .filter_map(|domain| domain.as_str().parse::<Domain>().ok())
        {
            for part in domain.iter_parent_domains() {
                self.extracted_domains.insert(part);
            }
            self.extracted_domains.insert(domain);
        }
        for ip in IP_REGEX
            .find_iter(data)
            .filter_map(|domain| domain.as_str().parse::<std::net::IpAddr>().ok())
        {
            self.extracted_ips.insert(ip);
        }
        match list_type {
            FilterListType::Adblock => data
                .lines()
                .for_each(|line| self.filter_builder.add_adblock_rule(line)),
            FilterListType::RegexAllowlist => data
                .lines()
                .for_each(|line| self.filter_builder.add_allow_regex(line)),
            FilterListType::RegexBlocklist => data
                .lines()
                .for_each(|line| self.filter_builder.add_disallow_regex(line)),
            FilterListType::DomainAllowlist => self.add_domain_list(data, true),
            FilterListType::DomainBlocklist => self.add_domain_list(data, false),
            FilterListType::IPBlocklist => data
                .lines()
                .filter_map(|line| line.split_whitespace().next())
                .filter_map(|ip| ip.split_terminator('#').next())
                .filter_map(|ip| ip.parse::<std::net::IpAddr>().ok())
                .for_each(|ip| self.filter_builder.add_disallow_ip_addr(ip)),
            FilterListType::IPAllowlist => data
                .lines()
                .filter_map(|line| line.split_whitespace().next())
                .filter_map(|ip| ip.split_terminator('#').next())
                .filter_map(|ip| ip.parse::<std::net::IpAddr>().ok())
                .for_each(|ip| self.filter_builder.add_allow_ip_addr(ip)),
            FilterListType::Hostfile => data
                .lines()
                .filter_map(|line| {
                    let mut parts = line.split_whitespace();
                    Some((parts.next()?, parts.next()?))
                })
                .filter(|(ip, _)| match *ip {
                    "0.0.0.0" => true,
                    "127.0.0.1" => true,
                    "::1" => true,
                    _ => false,
                })
                .filter_map(|(_, domain)| domain.split_terminator('#').next())
                .filter_map(|unprocessed| {
                    unprocessed
                        .trim_start_matches("*.")
                        .parse::<Domain>()
                        .ok()
                        .map(|domain| (domain, unprocessed.starts_with("*.")))
                })
                .for_each(|(domain, is_star_subdomain)| {
                    if is_star_subdomain {
                        self.filter_builder.add_disallow_subdomain(domain)
                    } else {
                        self.filter_builder.add_disallow_domain(domain)
                    }
                }),
            FilterListType::PrivacyBadger => {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&data) {
                    if let Some(action_map) =
                        json.get("action_map").and_then(|data| data.as_object())
                    {
                        for (domain, info) in action_map {
                            if info
                                .get("heuristicAction")
                                .and_then(|item| item.as_str())
                                .map(|item| item == "block")
                                .unwrap_or(false)
                            {
                                if let Ok(domain) = domain.parse() {
                                    self.filter_builder.add_disallow_domain(domain);
                                }
                            }
                        }
                    }
                }
            }
            list_type => println!("Unsupported list type: {:?}", list_type),
        }
    }
    pub fn to_filterlist(self) -> FilterList {
        let mut bc = FilterList {
            filter: self.filter_builder.to_domain_filter(),
            extracted_domains: self.extracted_domains,
            blocked_domains: Default::default(),
            allowed_domains: Default::default(),
            blocked_ip_addrs: Default::default(),
            allowed_ip_addrs: Default::default(),
        };
        bc.extracted_domains.shrink_to_fit();
        for ip in self.extracted_ips.into_iter() {
            if let Some(allowed) = bc.filter.ip_is_allowed(&ip) {
                if allowed {
                    bc.allowed_ip_addrs.insert(ip);
                } else {
                    bc.blocked_ip_addrs.insert(ip);
                }
            }
        }
        bc
    }
}

pub struct FilterList {
    filter: blockconvert::DomainFilter,
    blocked_domains: std::collections::HashSet<Domain>,
    allowed_domains: std::collections::HashSet<Domain>,
    blocked_ip_addrs: std::collections::HashSet<std::net::IpAddr>,
    allowed_ip_addrs: std::collections::HashSet<std::net::IpAddr>,
    extracted_domains: std::collections::HashSet<Domain>,
}

impl FilterList {
    pub fn from(filter_lists: &[(FilterListType, &str)]) -> Self {
        let mut builder = FilterListBuilder::new();
        for (list_type, data) in filter_lists.iter() {
            builder.add_list(*list_type, data)
        }
        builder.to_filterlist()
    }
    pub fn allowed(
        &self,
        domain: &Domain,
        cnames: &[Domain],
        ips: &[std::net::IpAddr],
    ) -> Option<bool> {
        self.filter.allowed(domain, cnames, ips)
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
        if let Some(allowed) = self.allowed(domain, cnames, ips) {
            if allowed {
                self.allowed_domains.insert(domain.clone())
            } else {
                self.blocked_domains.insert(domain.clone())
            };
        }
    }
    pub fn add_extracted_domain(&mut self, domain: Domain) {
        for part in domain.iter_parent_domains() {
            self.extracted_domains.insert(part);
        }
        self.extracted_domains.insert(domain);
    }

    pub async fn write_all(
        &self,
        blocked_domains_path: &std::path::Path,
        hostfile_path: &std::path::Path,
        rpz_path: &std::path::Path,
        adblock_path: &std::path::Path,
        allowed_domains_path: &std::path::Path,
        blocked_ip_addrs_path: &std::path::Path,
        allowed_ip_addrs_path: &std::path::Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        async fn write_to_file<T: std::fmt::Display + Ord, F: Fn(&T) -> String>(
            data: &std::collections::HashSet<T>,
            path: &std::path::Path,
            f: F,
        ) -> Result<(), Box<dyn std::error::Error>> {
            let file = async_std::fs::File::create(path).await?;
            let mut buf = BufWriter::new(file);
            let mut sorted: Vec<_> = data.iter().collect();
            sorted.sort_unstable();
            for item in sorted.into_iter() {
                buf.write_all(f(item).as_bytes()).await?;
                buf.write_all(b"\n").await?;
            }
            buf.flush().await?;
            Ok(())
        }
        let adblock_header: String = format!(
            "[Adblock Plus 2.0]
! Version: {:?}
! Title: BlockConvert
! Last modified: {:?}
! Expires: 1 days (update frequency)
! Homepage: https://github.com/mkb2091/blockconvert
! Licence: GPL-3.0
!
!-----------------------Filters-----------------------!
",
            chrono::Utc::today(),
            chrono::Utc::today(),
        );
        let other_header: String = format!(
            "# Title: BlockConvert
# Last modified: {:?}
# Expires: 1 days (update frequency)
# Homepage: https://github.com/mkb2091/blockconvert
# Licence: GPL-3.0
",
            chrono::Utc::today()
        );
        let mut blocked_domains: Vec<_> = self.blocked_domains.iter().collect();
        blocked_domains.sort_unstable();
        let mut blocked_ips: Vec<_> = self.blocked_ip_addrs.iter().collect();
        blocked_ips.sort_unstable();
        let domains = futures::future::try_join5(
            async {
                let file = async_std::fs::File::create(blocked_domains_path).await?;
                let mut buf = BufWriter::new(file);
                buf.write_all(other_header.as_bytes()).await?;
                for item in blocked_domains.iter() {
                    buf.write_all(item.to_string().as_bytes()).await?;
                    buf.write_all(b"\n").await?;
                }
                buf.flush().await?;
                Ok(())
            },
            async {
                let file = async_std::fs::File::create(hostfile_path).await?;
                let mut buf = BufWriter::new(file);
                buf.write_all(other_header.as_bytes()).await?;
                for item in blocked_domains.iter() {
                    buf.write_all(format!("0.0.0.0 {}", item).as_bytes())
                        .await?;
                    buf.write_all(b"\n").await?;
                }
                buf.flush().await?;
                Ok(())
            },
            async {
                let file = async_std::fs::File::create(rpz_path).await?;
                let mut buf = BufWriter::new(file);
                buf.write_all(other_header.as_bytes()).await?;
                for item in blocked_domains.iter() {
                    buf.write_all(format!("{} CNAME .", item).as_bytes())
                        .await?;
                    buf.write_all(b"\n").await?;
                }
                buf.flush().await?;
                Ok(())
            },
            async {
                let file = async_std::fs::File::create(adblock_path).await?;
                let mut buf = BufWriter::new(file);
                buf.write_all(adblock_header.as_bytes()).await?;
                'outer: for item in blocked_domains.iter() {
                    for parent in item.iter_parent_domains() {
                        if self.blocked_domains.contains(&parent) {
                            continue 'outer;
                            // As adblock blocks all subdomains,
                            // if parent domain is blocked then filter is redundant
                        }
                    }
                    buf.write_all(format!("||{}^", item).as_bytes()).await?;
                    buf.write_all(b"\n").await?;
                }
                for item in blocked_ips.iter() {
                    buf.write_all(format!("||{}^", item).as_bytes()).await?;
                    buf.write_all(b"\n").await?;
                }
                buf.flush().await?;
                Ok(())
            },
            write_to_file(&self.allowed_domains, allowed_domains_path, |item| {
                item.to_string()
            }),
        );
        let ips = futures::future::try_join(
            write_to_file(&self.blocked_ip_addrs, blocked_ip_addrs_path, |item| {
                item.to_string()
            }),
            write_to_file(&self.allowed_ip_addrs, allowed_ip_addrs_path, |item| {
                item.to_string()
            }),
        );

        futures::future::try_join(domains, ips).await.map(|_| ())
    }
}
