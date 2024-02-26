use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(transparent)]
pub struct Domain(Arc<str>);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DomainRule {
    #[serde(rename = "b")]
    Block(Domain),
    #[serde(rename = "a")]
    Allow(Domain),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InvalidRule {
    Domain,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rule {
    #[serde(rename = "d")]
    Domain(DomainRule),
    #[serde(rename = "a")]
    Adblock(Arc<str>),
    #[serde(rename = "u")]
    Unknown(Arc<str>),
    #[serde(rename = "i")]
    Invalid(InvalidRule),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(into = "(Arc<str>, Rule)")]
#[serde(from = "(Arc<str>, Rule)")]
pub struct RulePair {
    source: Arc<str>,
    rule: Rule,
}

impl RulePair {
    pub fn new(source: Arc<str>, rule: Rule) -> RulePair {
        RulePair { source, rule }
    }
    pub fn get_rule(&self) -> &Rule {
        &self.rule
    }
    pub fn get_source(&self) -> &Arc<str> {
        &self.source
    }
}
impl Into<(Arc<str>, Rule)> for RulePair {
    fn into(self) -> (Arc<str>, Rule) {
        (self.source, self.rule)
    }
}
impl From<(Arc<str>, Rule)> for RulePair {
    fn from((source, rule): (Arc<str>, Rule)) -> Self {
        Self { source, rule }
    }
}

fn parse_lines(contents: &str, parser: &dyn Fn(&str) -> Option<Rule>) -> Vec<RulePair> {
    let mut rules = vec![];
    for line in contents.lines() {
        let source = line;
        if line.is_empty() {
            continue;
        }
        if let Some(rule) = parser(line) {
            rules.push(RulePair {
                source: source.into(),
                rule: rule,
            });
        }
    }
    rules
}

fn parse_domain_list_line(line: &str, block: bool) -> Option<Rule> {
    let Some(line) = line.split('#').next() else {
        return None;
    };
    if line.is_empty() {
        return None;
    }
    let line = line.trim();
    let mut segments = line.split_whitespace();
    match (segments.next(), segments.next(), segments.next()) {
        (Some(domain), None, None) => {
            let domain = Domain(domain.into());
            let domain_rule = if block {
                DomainRule::Block(domain)
            } else {
                DomainRule::Allow(domain)
            };
            Some(Rule::Domain(domain_rule))
        }
        (Some("127.0.0.1") | Some("0.0.0.0"), Some(domain), None) => {
            let domain = Domain(domain.into());
            let domain_rule = DomainRule::Block(domain);
            Some(Rule::Domain(domain_rule))
        }
        _ => Some(Rule::Invalid(InvalidRule::Domain)),
    }
}

fn parse_domain_list(contents: &str, block: bool) -> Vec<RulePair> {
    parse_lines(contents, &|line| parse_domain_list_line(line, block))
}

fn parse_adblock_line(line: &str) -> Option<Rule> {
    Some(Rule::Unknown(line.into()))
}

fn parse_adblock(contents: &str) -> Vec<RulePair> {
    parse_lines(contents, &parse_adblock_line)
}

fn parse_unknown_lines(contents: &str) -> Vec<RulePair> {
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
        rules.push(RulePair {
            source: source.into(),
            rule: Rule::Unknown(line.into()),
        });
    }
    rules
}

pub fn parse_list(contents: &str, list_format: crate::FilterListType) -> Vec<RulePair> {
    match list_format {
        crate::FilterListType::Adblock => parse_adblock(contents),
        crate::FilterListType::DomainBlocklist => parse_domain_list(contents, true),
        crate::FilterListType::DomainAllowlist => parse_domain_list(contents, false),
        crate::FilterListType::IPBlocklist => parse_unknown_lines(contents),
        crate::FilterListType::IPAllowlist => parse_unknown_lines(contents),
        crate::FilterListType::IPNetBlocklist => parse_unknown_lines(contents),
        crate::FilterListType::DenyHosts => parse_unknown_lines(contents),
        crate::FilterListType::RegexAllowlist => parse_unknown_lines(contents),
        crate::FilterListType::RegexBlocklist => parse_unknown_lines(contents),
        crate::FilterListType::Hostfile => parse_domain_list(contents, true),
        crate::FilterListType::DNSRPZ => parse_unknown_lines(contents),
        crate::FilterListType::PrivacyBadger => vec![],
    }
}
