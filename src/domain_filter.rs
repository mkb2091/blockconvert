use crate::Domain;

use std::collections::HashSet;

#[derive(Default)]
pub struct DomainFilterBuilder {
    allow_domains: HashSet<Domain>,
    disallow_domains: HashSet<Domain>,
    allow_subdomains: HashSet<Domain>,
    disallow_subdomains: HashSet<Domain>,
    allow_ips: HashSet<std::net::IpAddr>,
    disallow_ips: HashSet<std::net::IpAddr>,
    allow_ip_net: HashSet<ipnet::IpNet>,
    disallow_ip_net: HashSet<ipnet::IpNet>,
    adblock: HashSet<String>,
    allow_regex: HashSet<String>,
    disallow_regex: HashSet<String>,
}

impl DomainFilterBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_allow_domain(&mut self, domain: Domain) {
        if let Some(without_www) = domain
            .strip_prefix("www.")
            .and_then(|domain| domain.parse::<Domain>().ok())
        {
            let _ = self.disallow_domains.remove(&without_www);
            self.allow_domains.insert(without_www);
        }
        let _ = self.disallow_domains.remove(&domain);
        self.allow_domains.insert(domain);
    }
    pub fn add_disallow_domain(&mut self, domain: Domain) {
        if !self.allow_domains.contains(&domain)
            && !is_subdomain_of_list(&domain, &self.allow_subdomains)
        {
            self.disallow_domains.insert(domain);
        }
    }
    pub fn add_allow_subdomain(&mut self, domain: Domain) {
        let _ = self.disallow_subdomains.remove(&domain);
        self.allow_subdomains.insert(domain);
    }
    pub fn add_disallow_subdomain(&mut self, domain: Domain) {
        if !self.allow_subdomains.contains(&domain) {
            self.disallow_subdomains.insert(domain);
        }
    }

    pub fn add_allow_ip_addr(&mut self, ip: std::net::IpAddr) {
        let _ = self.disallow_ips.remove(&ip);
        self.allow_ips.insert(ip);
    }
    pub fn add_disallow_ip_addr(&mut self, ip: std::net::IpAddr) {
        self.disallow_ips.insert(ip);
    }

    pub fn add_allow_ip_subnet(&mut self, net: ipnet::IpNet) {
        let _ = self.disallow_ip_net.remove(&net);
        self.allow_ip_net.insert(net);
    }

    pub fn add_disallow_ip_subnet(&mut self, ip: ipnet::IpNet) {
        self.disallow_ip_net.insert(ip);
    }

    pub fn add_adblock_rule(&mut self, rule: &str) {
        if let Some(inner) = rule
            .strip_prefix("||")
            .and_then(|rule| rule.strip_suffix("^"))
        {
            if let Ok(domain) = inner.parse::<Domain>() {
                self.add_disallow_domain(domain.clone());
                self.add_disallow_subdomain(domain);
                return;
            }
            if let Ok(ip) = inner.parse::<std::net::IpAddr>() {
                self.add_disallow_ip_addr(ip);
                return;
            }
        }
        self.adblock.insert(rule.to_string());
    }

    pub fn add_allow_regex(&mut self, re: &str) {
        if !re.is_empty() && regex::Regex::new(re).is_ok() {
            self.allow_regex.insert(re.to_string());
        }
    }
    pub fn add_disallow_regex(&mut self, re: &str) {
        if !re.is_empty() && regex::Regex::new(re).is_ok() {
            self.disallow_regex.insert(re.to_string());
        }
    }

    pub fn to_domain_filter(self) -> DomainFilter {
        let mut filter = DomainFilter {
            allow_domains: self.allow_domains,
            disallow_domains: self.disallow_domains,
            allow_subdomains: self.allow_subdomains,
            disallow_subdomains: self.disallow_subdomains,
            allow_ips: self.allow_ips,
            disallow_ips: self.disallow_ips,
            allow_ip_net: self.allow_ip_net.into_iter().collect(),
            disallow_ip_net: self.disallow_ip_net.into_iter().collect(),
            adblock: adblock::engine::Engine::from_rules_parametrised(
                &self.adblock.into_iter().collect::<Vec<String>>(),
                true,  // Network filters
                false, // Cosmetic filter
                false, // Debug mode
                false, // Optimise, enabling increases total program performance by ~10% but uses ~200MB
            ),
            allow_regex: regex::RegexSet::new(&self.allow_regex).unwrap(),
            disallow_regex: regex::RegexSet::new(&self.disallow_regex).unwrap(),
        };
        filter.allow_domains.shrink_to_fit();
        filter.disallow_domains.shrink_to_fit();
        filter.allow_subdomains.shrink_to_fit();
        filter.disallow_subdomains.shrink_to_fit();
        filter.allow_ips.shrink_to_fit();
        filter.disallow_ips.shrink_to_fit();
        filter.allow_ip_net.shrink_to_fit();
        filter.disallow_ip_net.shrink_to_fit();
        filter
    }
}

fn is_subdomain_of_list(domain: &Domain, filter_list: &std::collections::HashSet<Domain>) -> bool {
    domain
        .iter_parent_domains()
        .any(|part| filter_list.contains(&part))
}

#[allow(dead_code)]
pub struct DomainFilter {
    allow_domains: HashSet<Domain>,
    disallow_domains: HashSet<Domain>,
    allow_subdomains: HashSet<Domain>,
    disallow_subdomains: HashSet<Domain>,
    allow_ips: HashSet<std::net::IpAddr>,
    disallow_ips: HashSet<std::net::IpAddr>,
    allow_ip_net: Vec<ipnet::IpNet>,
    disallow_ip_net: Vec<ipnet::IpNet>,
    adblock: adblock::engine::Engine,
    allow_regex: regex::RegexSet,
    disallow_regex: regex::RegexSet,
}
#[allow(dead_code)]
impl DomainFilter {
    fn is_allowed_by_adblock(&self, location: &str) -> Option<bool> {
        let url = format!("https://{}", location);
        if let Ok(request) = adblock::request::Request::from_urls(&url, &url, "") {
            let blocker_result = self
                .adblock
                .blocker
                .check_parameterised(&request, false, true);
            if blocker_result.exception.is_some() {
                Some(true)
            } else if blocker_result.matched {
                Some(false)
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn allowed(
        &self,
        domain: &Domain,
        cnames: &[Domain],
        ips: &[std::net::IpAddr],
    ) -> Option<bool> {
        if let Some(result) = self.domain_is_allowed(domain) {
            Some(result)
        } else if cnames
            .iter()
            .any(|cname| self.domain_is_allowed(cname) == Some(false))
            || ips.iter().any(|ip| self.ip_is_allowed(ip) == Some(false))
        {
            Some(false)
        } else {
            None
        }
    }

    fn domain_is_allowed(&self, domain: &Domain) -> Option<bool> {
        if self.allow_domains.contains(domain)
            || is_subdomain_of_list(&*domain, &self.allow_subdomains)
            || self.allow_regex.is_match(domain)
        {
            Some(true)
        } else if let Some(blocker_result) = self.is_allowed_by_adblock(&domain) {
            Some(blocker_result)
        } else if self.disallow_domains.contains(domain)
            || is_subdomain_of_list(&*domain, &self.disallow_subdomains)
            || self.disallow_regex.is_match(domain)
        {
            Some(false)
        } else {
            None
        }
    }

    pub fn ip_is_allowed(&self, ip: &std::net::IpAddr) -> Option<bool> {
        if self.allow_ips.contains(ip) || self.allow_ip_net.iter().any(|net| net.contains(ip)) {
            Some(true)
        } else if let Some(blocker_result) = self.is_allowed_by_adblock(&ip.to_string()) {
            Some(blocker_result)
        } else if self.disallow_ips.contains(ip)
            || self.disallow_ip_net.iter().any(|net| net.contains(ip))
        {
            Some(false)
        } else {
            None
        }
    }
}

#[test]
fn default_unblocked() {
    assert_eq!(
        DomainFilterBuilder::new()
            .to_domain_filter()
            .domain_is_allowed(&"example.org".parse().unwrap()),
        None
    )
}

#[test]
fn regex_disallow_all_blocks_domain() {
    let mut filter = DomainFilterBuilder::new();
    filter.add_disallow_regex(".");
    let filter = filter.to_domain_filter();
    assert_eq!(
        filter.domain_is_allowed(&"example.org".parse().unwrap()),
        Some(false)
    )
}
#[test]
fn regex_allow_overrules_regex_disallow() {
    let mut filter = DomainFilterBuilder::new();
    filter.add_disallow_regex(".");
    filter.add_allow_regex(".");
    let filter = filter.to_domain_filter();
    assert_eq!(
        filter.domain_is_allowed(&"example.org".parse().unwrap()),
        Some(true)
    )
}

#[test]
fn adblock_can_block_domain() {
    let mut filter = DomainFilterBuilder::new();
    filter.add_adblock_rule("||example.com^");
    let filter = filter.to_domain_filter();
    assert_eq!(
        filter.domain_is_allowed(&"example.com".parse().unwrap()),
        Some(false)
    )
}

#[test]
fn adblock_can_whitelist_blocked_domain() {
    let mut filter = DomainFilterBuilder::new();
    filter.add_disallow_regex(".");
    filter.add_adblock_rule("@@||example.com^");
    let filter = filter.to_domain_filter();
    assert_eq!(
        filter.domain_is_allowed(&"example.com".parse().unwrap()),
        Some(true)
    )
}

#[test]
fn subdomain_disallow_blocks() {
    let mut filter = DomainFilterBuilder::new();
    filter.add_disallow_subdomain("example.com".parse().unwrap());
    let filter = filter.to_domain_filter();
    assert_eq!(
        filter.domain_is_allowed(&"www.example.com".parse().unwrap()),
        Some(false)
    )
}

#[test]
fn subdomain_allow_whitelists_domains() {
    let mut filter = DomainFilterBuilder::new();
    filter.add_disallow_regex(".");
    filter.add_allow_subdomain("example.com".parse().unwrap());
    let filter = filter.to_domain_filter();
    assert_eq!(
        filter.domain_is_allowed(&"www.example.com".parse().unwrap()),
        Some(true)
    )
}

#[test]
fn subdomain_disallow_does_not_block_domain() {
    let mut filter = DomainFilterBuilder::new();
    filter.add_disallow_subdomain("example.com".parse().unwrap());
    let filter = filter.to_domain_filter();
    assert_eq!(
        filter.domain_is_allowed(&"example.com".parse().unwrap()),
        None
    )
}

#[test]
fn blocked_cname_blocks_base() {
    let mut filter = DomainFilterBuilder::new();
    filter.add_disallow_domain("tracker.com".parse().unwrap());
    let filter = filter.to_domain_filter();
    assert_eq!(
        filter.allowed(
            &"example.com".parse().unwrap(),
            &["tracker.com".parse().unwrap()],
            &[]
        ),
        Some(false)
    )
}

#[test]
fn blocked_ip_blocks_base() {
    let mut filter = DomainFilterBuilder::new();
    filter.add_disallow_ip_addr("8.8.8.8".parse().unwrap());
    let filter = filter.to_domain_filter();
    assert_eq!(
        filter.allowed(
            &"example.com".parse().unwrap(),
            &[],
            &["8.8.8.8".parse().unwrap()]
        ),
        Some(false)
    )
}

#[test]
fn ignores_allowed_ips() {
    let mut filter = DomainFilterBuilder::new();
    filter.add_disallow_domain("example.com".parse().unwrap());
    filter.add_allow_ip_addr("8.8.8.8".parse().unwrap());
    let filter = filter.to_domain_filter();
    assert_eq!(
        filter.allowed(
            &"example.com".parse().unwrap(),
            &[],
            &["8.8.8.8".parse().unwrap()]
        ),
        Some(false)
    )
}

#[test]
fn unblocked_ips_do_not_allow() {
    let mut filter = DomainFilterBuilder::new();
    filter.add_allow_ip_addr("8.8.8.8".parse().unwrap());
    let filter = filter.to_domain_filter();
    assert_eq!(
        filter.allowed(
            &"example.com".parse().unwrap(),
            &[],
            &["8.8.8.8".parse().unwrap()]
        ),
        None
    )
}

#[test]
fn adblock_third_party_does_not_block_domain() {
    let mut filter = DomainFilterBuilder::new();
    filter.add_adblock_rule("||example.com$third-party");
    let filter = filter.to_domain_filter();
    assert_eq!(
        filter.domain_is_allowed(&"example.com".parse().unwrap()),
        None
    );
    assert_eq!(
        filter.domain_is_allowed(&"www.example.com".parse().unwrap()),
        None
    )
}
