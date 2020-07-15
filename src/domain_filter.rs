use crate::Domain;

pub struct DomainFilterBuilder {
    allow_subdomains: std::collections::HashSet<Domain>,
    disallow_subdomains: std::collections::HashSet<Domain>,
    adblock: std::collections::HashSet<String>,
    allow_regex: std::collections::HashSet<String>,
    disallow_regex: std::collections::HashSet<String>,
}

impl DomainFilterBuilder {
    pub fn new() -> Self {
        Self {
            allow_subdomains: std::collections::HashSet::new(),
            disallow_subdomains: std::collections::HashSet::new(),
            adblock: std::collections::HashSet::new(),
            allow_regex: std::collections::HashSet::new(),
            disallow_regex: std::collections::HashSet::new(),
        }
    }

    pub fn add_allow_subdomain(&mut self, base_domain: &str) {
        if let Ok(domain) = base_domain.trim_start_matches("*.").parse::<Domain>() {
            self.allow_subdomains.insert(domain);
        }
    }
    pub fn add_disallow_subdomain(&mut self, base_domain: &str) {
        if let Ok(domain) = base_domain.trim_start_matches("*.").parse::<Domain>() {
            self.disallow_subdomains.insert(domain);
        }
    }

    pub fn add_adblock_rule(&mut self, rule: &str) {
        self.adblock.insert(rule.to_string());
    }

    pub fn add_allow_regex(&mut self, re: &str) {
        if regex::Regex::new(re).is_ok() {
            self.allow_regex.insert(re.to_string());
        }
    }
    pub fn add_disallow_regex(&mut self, re: &str) {
        if regex::Regex::new(re).is_ok() {
            self.disallow_regex.insert(re.to_string());
        }
    }

    pub fn to_domain_filter(&self) -> DomainFilter {
        DomainFilter {
            allow_subdomains: self.allow_subdomains.clone(),
            disallow_subdomains: self.disallow_subdomains.clone(),
            adblock: adblock::engine::Engine::from_rules(
                &self.adblock.iter().cloned().collect::<Vec<String>>(),
            ),
            allow_regex: regex::RegexSet::new(&self.allow_regex).unwrap(),
            disallow_regex: regex::RegexSet::new(&self.disallow_regex).unwrap(),
        }
    }
}

fn is_subdomain(domain: &Domain, filter_list: &std::collections::HashSet<Domain>) -> bool {
    domain
        .iter_parent_domains()
        .any(|part| filter_list.contains(&part))
}

#[allow(dead_code)]
pub struct DomainFilter {
    allow_subdomains: std::collections::HashSet<Domain>,
    disallow_subdomains: std::collections::HashSet<Domain>,
    adblock: adblock::engine::Engine,
    allow_regex: regex::RegexSet,
    disallow_regex: regex::RegexSet,
}
#[allow(dead_code)]
impl DomainFilter {
    pub fn allowed<'b>(&self, domain: &Domain) -> Option<bool> {
        if self.allow_regex.is_match(domain) || is_subdomain(&*domain, &self.allow_subdomains) {
            return Some(true);
        }
        let url = format!("https://{}", domain);
        let blocker_result = self.adblock.check_network_urls(&url, &url, "");
        if blocker_result.exception.is_some() {
            // Adblock exception rule
            Some(true)
        } else if blocker_result.matched
            || self.disallow_regex.is_match(domain)
            || is_subdomain(&*domain, &self.disallow_subdomains)
        {
            Some(false)
        } else {
            None
        }
    }
    pub fn allowed_str(&self, domain: &str) -> Option<bool> {
        if let Ok(domain) = domain.parse::<Domain>() {
            self.allowed(&domain)
        } else {
            None
        }
    }
    pub fn allowed_ip(&self, ip: std::net::IpAddr) -> Option<bool> {
        let url = format!("http://{}", ip);
        let blocker_result = self.adblock.check_network_urls(&url, &url, "");
        if blocker_result.exception.is_some() {
            // Adblock exception rule
            Some(true)
        } else if blocker_result.matched {
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
            .allowed_str("example.org"),
        None
    )
}

#[test]
fn regex_disallow_all_blocks_domain() {
    let mut filter = DomainFilterBuilder::new();
    filter.add_disallow_regex(".");
    let filter = filter.to_domain_filter();
    assert_eq!(filter.allowed_str("example.org"), Some(false))
}
#[test]
fn regex_allow_overrules_regex_disallow() {
    let mut filter = DomainFilterBuilder::new();
    filter.add_disallow_regex(".");
    filter.add_allow_regex(".");
    let filter = filter.to_domain_filter();
    assert_eq!(filter.allowed_str("example.org"), Some(true))
}

#[test]
fn adblock_can_block_domain() {
    let mut filter = DomainFilterBuilder::new();
    filter.add_adblock_rule("||example.com^");
    let filter = filter.to_domain_filter();
    assert_eq!(filter.allowed_str("example.com"), Some(false))
}

#[test]
fn adblock_can_whitelist_blocked_domain() {
    let mut filter = DomainFilterBuilder::new();
    filter.add_disallow_regex(".");
    // Due to the adblock rule optimiser,
    // exception rules which don't overlap with block rules are ignored
    filter.add_adblock_rule("||example.com^");
    filter.add_adblock_rule("@@||example.com^");
    let filter = filter.to_domain_filter();
    assert_eq!(filter.allowed_str("example.com"), Some(true))
}

#[test]
fn subdomain_disallow_blocks() {
    let mut filter = DomainFilterBuilder::new();
    filter.add_disallow_subdomain("example.com");
    let filter = filter.to_domain_filter();
    assert_eq!(filter.allowed_str("www.example.com"), Some(false))
}

#[test]
fn subdomain_allow_whitelists_domains() {
    let mut filter = DomainFilterBuilder::new();
    filter.add_disallow_regex(".");
    filter.add_allow_subdomain("example.com");
    let filter = filter.to_domain_filter();
    assert_eq!(filter.allowed_str("www.example.com"), Some(true))
}

#[test]
fn subdomain_disallow_does_not_block_domain() {
    let mut filter = DomainFilterBuilder::new();
    filter.add_disallow_subdomain("example.com");
    let filter = filter.to_domain_filter();
    assert_eq!(filter.allowed_str("example.com"), None)
}
