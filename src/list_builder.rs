use crate::{
    dns_lookup, ipnet, DBReadHandler, Domain, DomainSetShardedFX, FilterListRecord, FilterListType,
    DOMAIN_REGEX, IP_REGEX,
};

use crate::dns_lookup::{DNSResultRecord, DomainRecordHandler};
use crate::list_downloader::FilterListHandler;

use parking_lot::Mutex;
use std::sync::Arc;

use tokio::io::BufWriter;

use tokio::io::AsyncWriteExt;

type DomainFilterBuilderFX = blockconvert::DomainFilterBuilder<fxhash::FxBuildHasher>;

pub struct FilterListBuilder {
    filter_builder: DomainFilterBuilderFX,
    pub extracted_domains: DomainSetShardedFX,
    pub extracted_ips: Mutex<std::collections::HashSet<std::net::IpAddr>>,
}

impl Default for FilterListBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl FilterListBuilder {
    pub fn new() -> Self {
        Self {
            filter_builder: Default::default(),
            extracted_domains: DomainSetShardedFX::with_shards(8192),
            extracted_ips: Default::default(),
        }
    }
    fn add_domain_list(&self, data: &str, is_allow_list: bool) {
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

    pub fn add_list(&self, list_type: FilterListType, data: &str) {
        for domain in DOMAIN_REGEX
            .find_iter(data)
            .filter_map(|domain| domain.as_str().parse::<Domain>().ok())
        {
            for part in domain.iter_parent_domains() {
                self.extracted_domains.insert_str(&part);
            }
            self.extracted_domains.insert_str(&domain);
        }
        let mut extracted_ips = self.extracted_ips.lock();
        for ip in IP_REGEX
            .find_iter(data)
            .filter_map(|domain| domain.as_str().parse::<std::net::IpAddr>().ok())
        {
            extracted_ips.insert(ip);
        }
        drop(extracted_ips);
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
            FilterListType::IPNetBlocklist => data
                .lines()
                .filter_map(|line| line.split_whitespace().next())
                .filter_map(|ip| ip.split_terminator('#').next())
                .filter_map(|ip| ip.parse::<ipnet::IpNet>().ok())
                .for_each(|ip| self.filter_builder.add_disallow_ip_subnet(ip)),
            FilterListType::DenyHosts => data
                .lines()
                .filter_map(|line| line.strip_prefix("sshd: "))
                .filter_map(|line| line.parse().ok())
                .for_each(|ip| self.filter_builder.add_disallow_ip_addr(ip)),
            FilterListType::Hostfile => data
                .lines()
                .filter_map(|line| line.split('#').next())
                .filter_map(|line| {
                    let mut parts = line.split_whitespace();
                    Some((parts.next()?, parts.next()?))
                })
                .filter(|(ip, _)| matches!(*ip, "0.0.0.0" | "127.0.0.1" | "::1"))
                .map(|(_, domain)| domain)
                .filter_map(|unprocessed| {
                    unprocessed
                        .strip_prefix("*.")
                        .and_then(|domain| {
                            domain.parse::<Domain>().ok().map(|domain| (domain, true))
                        })
                        .or_else(|| {
                            unprocessed
                                .parse::<Domain>()
                                .ok()
                                .map(|domain| (domain, false))
                        })
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
        let bc = FilterList {
            filter: self.filter_builder.to_domain_filter(),
            extracted_domains: self.extracted_domains,
            blocked_domains: DomainSetShardedFX::with_shards(1024),
            allowed_domains: DomainSetShardedFX::with_shards(128),
            blocked_ip_addrs: Default::default(),
            allowed_ip_addrs: Default::default(),
        };
        for ip in self.extracted_ips.lock().iter() {
            if let Some(allowed) = bc.filter.ip_is_allowed(&ip) {
                if allowed {
                    bc.allowed_ip_addrs.lock().insert(*ip);
                } else {
                    bc.blocked_ip_addrs.lock().insert(*ip);
                }
            }
        }
        bc.blocked_ip_addrs.lock().shrink_to_fit();
        bc.allowed_ip_addrs.lock().shrink_to_fit();
        bc
    }
}

impl FilterListHandler for FilterListBuilder {
    fn handle_filter_list(&self, record: FilterListRecord, data: &str) {
        self.add_list(record.list_type, data);
    }
}

#[derive(Default)]
pub struct FilterList {
    filter: blockconvert::DomainFilter<fxhash::FxBuildHasher>,
    blocked_domains: DomainSetShardedFX,
    allowed_domains: DomainSetShardedFX,
    blocked_ip_addrs: Mutex<std::collections::HashSet<std::net::IpAddr>>,
    allowed_ip_addrs: Mutex<std::collections::HashSet<std::net::IpAddr>>,
    extracted_domains: DomainSetShardedFX,
}

impl FilterList {
    pub fn from(filter_lists: &[(FilterListType, &str)]) -> Self {
        let builder = FilterListBuilder::new();
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
        self.extracted_domains.shrink_to_fit();
        let servers: Vec<Arc<String>> = servers
            .iter()
            .map(|server| Arc::new(server.clone()))
            .collect();
        let extracted_domains = std::mem::replace(
            &mut self.extracted_domains,
            DomainSetShardedFX::with_shards(0),
        );
        let mem_take_self = Arc::new(std::mem::take(self));

        let _ = dns_lookup::lookup_domains(
            extracted_domains,
            mem_take_self.clone(),
            &servers[..],
            client,
        )
        .await;
        let _ = std::mem::replace(
            self,
            Arc::try_unwrap(mem_take_self)
                .ok()
                .expect("Failed to unwrap Arc"),
        );
    }

    pub fn finished_extracting(&self) {
        println!("Extracted domains: {:?}", self.extracted_domains.len());
    }

    pub async fn write_all(
        self,
        blocked_domains_path: &std::path::Path,
        hostfile_path: &std::path::Path,
        rpz_path: &std::path::Path,
        adblock_path: &std::path::Path,
        allowed_adblock_path: &std::path::Path,
        allowed_domains_path: &std::path::Path,
        blocked_ip_addrs_path: &std::path::Path,
        allowed_ip_addrs_path: &std::path::Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        async fn write_to_file(
            mut data: Vec<String>,
            path: &std::path::Path,
        ) -> Result<(), Box<dyn std::error::Error>> {
            let file = tokio::fs::File::create(path).await?;
            let mut buf = BufWriter::new(file);
            data.sort_unstable_by(|domain1, domain2| {
                Domain::str_iter_parent_domains(domain1)
                    .rev()
                    .chain(std::iter::once(domain1.as_str()))
                    .cmp(
                        Domain::str_iter_parent_domains(domain2)
                            .rev()
                            .chain(std::iter::once(domain2.as_str())),
                    )
            });
            for item in data.into_iter() {
                buf.write_all(item.as_bytes()).await?;
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
        let adblock_whitelist_header: String = format!(
            "[Adblock Plus 2.0]
! Version: {:?}
! Title: BlockConvert Exception Filters
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
        let blocked_domains_base: std::collections::HashSet<Domain> =
            self.blocked_domains.into_iter_domains().collect();
        let mut blocked_domains: Vec<Domain> = blocked_domains_base.iter().cloned().collect();
        blocked_domains.sort_unstable_by(|domain1, domain2| {
            Domain::str_iter_parent_domains(domain1)
                .rev()
                .chain(std::iter::once(domain1.as_str()))
                .cmp(
                    Domain::str_iter_parent_domains(domain2)
                        .rev()
                        .chain(std::iter::once(domain2.as_str())),
                )
        });

        let mut allowed_domains: Vec<Domain> = self.allowed_domains.into_iter_domains().collect();
        allowed_domains.sort_unstable_by(|domain1, domain2| {
            Domain::str_iter_parent_domains(domain1)
                .rev()
                .chain(std::iter::once(domain1.as_str()))
                .cmp(
                    Domain::str_iter_parent_domains(domain2)
                        .rev()
                        .chain(std::iter::once(domain2.as_str())),
                )
        });

        let blocked_ip_addrs_base = self.blocked_ip_addrs.lock();
        let mut blocked_ips: Vec<_> = blocked_ip_addrs_base.iter().collect();
        blocked_ips.sort_unstable();

        let allowed_ip_addrs_base = self.allowed_ip_addrs.lock();
        let mut allowed_ips: Vec<_> = allowed_ip_addrs_base.iter().collect();
        allowed_ips.sort_unstable();

        let domains = futures::future::try_join4(
            async {
                let file = tokio::fs::File::create(blocked_domains_path).await?;
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
                let file = tokio::fs::File::create(hostfile_path).await?;
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
                let file = tokio::fs::File::create(rpz_path).await?;
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
                let file = tokio::fs::File::create(adblock_path).await?;
                let mut buf = BufWriter::new(file);
                buf.write_all(adblock_header.as_bytes()).await?;
                'outer: for item in blocked_domains.iter() {
                    for parent in item.iter_parent_domains() {
                        if blocked_domains_base.contains(&parent) {
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
        );
        let whitelist = futures::future::try_join(
            async {
                let file = tokio::fs::File::create(allowed_adblock_path).await?;
                let mut buf = BufWriter::new(file);
                buf.write_all(adblock_whitelist_header.as_bytes()).await?;
                for item in allowed_domains.iter() {
                    buf.write_all(format!("@@||{}^", item).as_bytes()).await?;
                    buf.write_all(b"\n").await?;
                }
                buf.flush().await?;
                Ok(())
            },
            write_to_file(
                allowed_domains
                    .iter()
                    .map(|item| item.to_string())
                    .collect(),
                allowed_domains_path,
            ),
        );
        let ips = futures::future::try_join(
            write_to_file(
                blocked_ips.iter().map(|item| item.to_string()).collect(),
                blocked_ip_addrs_path,
            ),
            write_to_file(
                allowed_ips.iter().map(|item| item.to_string()).collect(),
                allowed_ip_addrs_path,
            ),
        );

        futures::future::try_join3(domains, whitelist, ips)
            .await
            .map(|_| ())
    }
}

impl DBReadHandler for FilterList {
    fn handle_input(&self, data: &str) {
        let data = data.trim_end();
        if Domain::str_is_valid_domain(data).is_ok() {
            if !self.extracted_domains.insert_str(data) {
                return; // Already contains parent domain, no need to continue inserting children
            }
            for sub_domain in Domain::str_iter_parent_domains(data) {
                if !self.extracted_domains.insert_str(sub_domain) {
                    return;
                }
            }
        }
    }
}

impl DomainRecordHandler for FilterList {
    fn handle_domain_record(&self, record: &DNSResultRecord) {
        if record.ips.is_empty() {
            return;
        }
        if let Some(allowed) = self
            .filter
            .allowed(&record.domain, &record.cnames, &record.ips)
        {
            if allowed {
                self.allowed_domains.insert_str(&record.domain)
            } else {
                self.blocked_domains.insert_str(&record.domain)
            };
        }
    }
}

#[test]
fn normal_is_ok() {
    let builder = FilterListBuilder::default();
    let filter_list = builder.to_filterlist();
    assert_eq!(filter_list.extracted_domains.len(), 0);
}
