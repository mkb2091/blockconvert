use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(transparent)]
pub struct Domain(Arc<str>);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DomainRule {
    Block(Domain),
    Allow(Domain),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rule {
    Domain(DomainRule),
    Unknown(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RulePair {
    source: String,
    rule: Rule,
}

impl RulePair {
    pub fn new(source: String, rule: Rule) -> RulePair {
        RulePair { source, rule }
    }
    pub fn get_rule(&self) -> &Rule {
        &self.rule
    }
    pub fn get_source(&self) -> &String {
        &self.source
    }
}

fn parse_domain_list(contents: &str, block: bool) -> Vec<RulePair> {
    let mut rules = vec![];
    for line in contents.lines() {
        let source = line;
        let Some(line) = line.split('#').next() else {
            continue;
        };
        if line.is_empty() {
            continue;
        }
        let line = line.trim();
        let domain = Domain(line.into());
        let domain_rule = if block {
            DomainRule::Block(domain)
        } else {
            DomainRule::Allow(domain)
        };
        rules.push(RulePair {
            source: source.to_string(),
            rule: Rule::Domain(domain_rule),
        });
    }
    rules
}

fn parse_hostfile(contents: &str) -> Vec<RulePair> {
    let mut rules = vec![];
    for line in contents.lines() {
        let source = line;
        let Some(line) = line.split('#').next() else {
            continue;
        };
        if line.is_empty() {
            continue;
        }
        let mut line = line.split_whitespace();
        let (Some(ip), Some(domain), None) = (line.next(), line.next(), line.next()) else {
            continue;
        };
        if ip != "127.0.0.1" {
            continue;
        }
        let domain = Domain(domain.into());
        let domain_rule = DomainRule::Block(domain);
        rules.push(RulePair {
            source: source.to_string(),
            rule: Rule::Domain(domain_rule),
        });
    }
    rules
}

pub fn parse_list(contents: &str, list_format: crate::FilterListType) -> Vec<RulePair> {
    match list_format {
        crate::FilterListType::Adblock => vec![],
        crate::FilterListType::DomainBlocklist => parse_domain_list(contents, true),
        crate::FilterListType::DomainAllowlist => parse_domain_list(contents, false),
        crate::FilterListType::IPBlocklist => vec![],
        crate::FilterListType::IPAllowlist => vec![],
        crate::FilterListType::IPNetBlocklist => vec![],
        crate::FilterListType::DenyHosts => vec![],
        crate::FilterListType::RegexAllowlist => vec![],
        crate::FilterListType::RegexBlocklist => vec![],
        crate::FilterListType::Hostfile => parse_hostfile(contents),
        crate::FilterListType::DNSRPZ => vec![],
        crate::FilterListType::PrivacyBadger => vec![],
    }
}
