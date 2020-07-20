use crate::{dns_lookup, domain_filter, Domain, FilterListType, DOMAIN_REGEX, IP_REGEX};

use async_std::io::BufWriter;
use async_std::prelude::*;

#[derive(Default)]
pub struct BlockConvertBuilder {
    filter_builder: domain_filter::DomainFilterBuilder,
    extracted_domains: std::collections::HashSet<Domain>,
    extracted_ips: std::collections::HashSet<std::net::IpAddr>,
}

impl BlockConvertBuilder {
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
            list_type => println!("Unsupported list type: {:?}", list_type),
        }
    }
    pub fn to_blockconvert(self) -> BlockConvert {
        let mut bc = BlockConvert {
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

pub struct BlockConvert {
    filter: domain_filter::DomainFilter,
    blocked_domains: std::collections::HashSet<Domain>,
    allowed_domains: std::collections::HashSet<Domain>,
    blocked_ip_addrs: std::collections::HashSet<std::net::IpAddr>,
    allowed_ip_addrs: std::collections::HashSet<std::net::IpAddr>,
    extracted_domains: std::collections::HashSet<Domain>,
}

impl BlockConvert {
    pub fn from(filter_lists: &[(FilterListType, &str)]) -> Self {
        let mut builder = BlockConvertBuilder::new();
        for (list_type, data) in filter_lists.iter() {
            builder.add_list(*list_type, data)
        }
        builder.to_blockconvert()
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
        blocked_domains: &std::path::Path,
        hostfile: &std::path::Path,
        rpz: &std::path::Path,
        adblock: &std::path::Path,
        allowed_domains: &std::path::Path,
        blocked_ip_addrs: &std::path::Path,
        allowed_ip_addrs: &std::path::Path,
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

        let domains = futures::future::try_join5(
            write_to_file(&self.blocked_domains, blocked_domains, |item| {
                item.to_string()
            }),
            write_to_file(&self.blocked_domains, hostfile, |item| {
                format!("0.0.0.0 {}", item)
            }),
            write_to_file(&self.blocked_domains, rpz, |item| {
                format!("{} CNAME .", item)
            }),
            write_to_file(&self.blocked_domains, adblock, |item| {
                format!("||{}^", item)
            }),
            write_to_file(&self.allowed_domains, allowed_domains, |item| {
                item.to_string()
            }),
        );
        let ips = futures::future::try_join(
            write_to_file(&self.blocked_ip_addrs, blocked_ip_addrs, |item| {
                item.to_string()
            }),
            write_to_file(&self.allowed_ip_addrs, allowed_ip_addrs, |item| {
                item.to_string()
            }),
        );

        futures::future::try_join(domains, ips).await.map(|_| ())
    }
}
