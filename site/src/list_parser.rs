use leptos::*;

use serde::{Deserialize, Serialize};

use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(transparent)]
pub struct Domain(Arc<str>);

impl AsRef<str> for Domain {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl TryInto<Domain> for &str {
    type Error = DomainParseError;
    fn try_into(self) -> Result<Domain, Self::Error> {
        let domain = addr::parse_dns_name(self)?;
        if !domain.has_known_suffix() || domain.root().is_none() {
            return Err(DomainParseError);
        }
        let domain_str: Arc<str> = domain.as_str().into();
        if domain_str.contains('/') {
            log::warn!("Invalid domain: {:?}", domain_str);
            return Err(DomainParseError);
        }
        assert!(domain_str.contains('.'));
        Ok(Domain(domain_str))
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub struct DomainParseError;

impl std::fmt::Display for DomainParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Invalid domain")
    }
}

impl<'a> From<addr::error::Error<'a>> for DomainParseError {
    fn from(_: addr::error::Error) -> Self {
        DomainParseError
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DomainRule {
    pub domain: Domain,
    pub allow: bool,
    pub subdomain: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IpRule {
    pub ip: ipnetwork::IpNetwork,
    pub allow: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rule {
    #[serde(rename = "d")]
    Domain(DomainRule),
    IpRule(IpRule),
    #[serde(rename = "u")]
    Unknown,
    #[serde(rename = "i")]
    Invalid,
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
impl From<RulePair> for (Arc<str>, Rule) {
    fn from(val: RulePair) -> Self {
        (val.source, val.rule)
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
                rule,
            });
        }
    }
    rules
}

fn parse_domain_list_line(line: &str, allow: bool, subdomain: bool) -> Option<Rule> {
    let line = line.split('#').next()?;
    if line.is_empty() {
        return None;
    }
    let line = line.trim();
    let mut segments = line.split_whitespace();
    match (segments.next(), segments.next(), segments.next()) {
        (Some(domain), None, None) | (Some("127.0.0.1") | Some("0.0.0.0"), Some(domain), None) => {
            if let Ok(domain) = domain.try_into() {
                let domain_rule = DomainRule {
                    domain,
                    allow,
                    subdomain,
                };
                Some(Rule::Domain(domain_rule))
            } else {
                Some(Rule::Invalid)
            }
        }
        _ => Some(Rule::Invalid),
    }
}

fn parse_domain_list(contents: &str, allow: bool, subdomain: bool) -> Vec<RulePair> {
    parse_lines(contents, &|line| {
        parse_domain_list_line(line, allow, subdomain)
    })
}

fn parse_adblock_line(line: &str) -> Option<Rule> {
    let rule = line;
    if rule.starts_with('!') // Comment
        || rule.contains('#') // CSS selector
        || !rule.trim_matches('.').contains('.') // Not a domain
        || matches! {rule, "[Adblock Plus 2.0]" | "[Adblock Plus 1.1]"}
    {
        return None;
    }

    let mut match_end_domain = false;

    let rule = if let Some((start, tags)) = rule.split_once('$') {
        let mut block_site = false;
        let mut has_specific_filters = false;
        let mut has_unknown_tag = false;
        for tag in tags.split(',') {
            if tag.starts_with('~') // Can't partially block a site
            || tag.starts_with("rewrite=")
            // Can't rewrite a site
            {
                return None;
            } else if let Some(domain_tag) = tag.strip_prefix("domain=") {
                for domain in domain_tag.split('|') {
                    if !start.contains(domain) {
                        return None;
                    }
                }
            } else {
                match tag {
                    "3p" | "third-party" | "doc" | "document" | "all" => {
                        match_end_domain = true;
                        block_site = true;
                    }
                    "popup" | "ghide" | "generichide" | "genericblock" | "image" | "script"
                    | "xmlhttprequest" | "stylesheet" | "subdocument" | "media" | "csp" => {
                        has_specific_filters = true;
                    }
                    "important" => {}
                    _ => {
                        has_unknown_tag = true;
                    }
                }
            }
        }
        if has_specific_filters & !block_site {
            return None;
        }
        if has_unknown_tag {
            return Some(Rule::Unknown);
        }
        start
    } else {
        rule
    };

    if let Some(rule) = rule.strip_prefix('/') {
        if let Some(_rule) = rule.strip_suffix('/') {
            // REGEX
        } else {
            return None; // Path selector
        }
    }
    let (rule, exception) = if let Some(rule) = rule.strip_prefix("@@") {
        (rule, true)
    } else {
        (rule, false)
    };
    let (rule, match_start_domain, match_exact_start) = if let Some(rule) = rule.strip_prefix("||")
    {
        (rule, true, false)
    } else {
        let (rule, match_exact_start) = rule
            .strip_prefix('|')
            .map(|rule| (rule, true))
            .unwrap_or((rule, false));
        (rule, false, match_exact_start)
    };

    let (rule, match_end_domain_exact) = rule
        .strip_suffix('|')
        .map(|rule| (rule, true))
        .unwrap_or((rule, false));
    let (rule, match_end_domain) = rule
        .strip_suffix('^')
        .map(|rule| (rule, true))
        .unwrap_or((rule, match_end_domain));
    if rule.contains('/') {
        return None; // Path selector
    }
    if rule.contains('*') {
        return Some(Rule::Unknown);
    }
    if match_start_domain && (match_end_domain | match_end_domain_exact) {
        if let Ok(domain) = rule.try_into() {
            let domain_rule = DomainRule {
                domain,
                allow: exception,
                subdomain: !match_exact_start,
            };
            return Some(Rule::Domain(domain_rule));
        } else if let Ok(ip) = rule.parse::<ipnetwork::IpNetwork>() {
            return Some(Rule::IpRule(IpRule {
                ip,
                allow: exception,
            }));
        }
    }
    Some(Rule::Unknown)
}

fn parse_adblock(contents: &str) -> Vec<RulePair> {
    parse_lines(contents, &parse_adblock_line)
}

fn parse_regex_line(line: &str) -> Option<Rule> {
    if line.starts_with('#') {
        return None;
    }
    if let Some(rule) = line.strip_prefix(r#"(^|\.)"#) {
        if let Some(rule) = rule.strip_suffix('$') {
            let mut rule = rule.to_string();
            rule.retain(|c| c != '/');
            if let Ok(domain) = rule.as_str().try_into() {
                let domain_rule = DomainRule {
                    domain,
                    allow: false,
                    subdomain: true,
                };
                return Some(Rule::Domain(domain_rule));
            }
        }
    }
    Some(Rule::Unknown)
}

fn parse_ip_network_line(line: &str, allow: bool) -> Option<Rule> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    if let Ok(ip) = line.parse::<ipnetwork::IpNetwork>() {
        Some(Rule::IpRule(IpRule { ip, allow }))
    } else {
        Some(Rule::Unknown)
    }
}

fn parse_ip_network_list(contents: &str, allow: bool) -> Vec<RulePair> {
    parse_lines(contents, &|line| parse_ip_network_line(line, allow))
}

fn parse_regex(contents: &str) -> Vec<RulePair> {
    parse_lines(contents, &parse_regex_line)
}

fn parse_unknown_lines(contents: &str) -> Vec<RulePair> {
    parse_lines(contents, &|_| Some(Rule::Unknown))
}

pub fn parse_list_contents(contents: &str, list_format: crate::FilterListType) -> Vec<RulePair> {
    match list_format {
        crate::FilterListType::Adblock => parse_adblock(contents),
        crate::FilterListType::DomainBlocklist => parse_domain_list(contents, false, true),
        crate::FilterListType::DomainAllowlist => parse_domain_list(contents, true, false),
        crate::FilterListType::IPBlocklist => parse_ip_network_list(contents, false),
        crate::FilterListType::IPAllowlist => parse_ip_network_list(contents, true),
        crate::FilterListType::IPNetBlocklist => parse_ip_network_list(contents, false),
        crate::FilterListType::DenyHosts => parse_unknown_lines(contents),
        crate::FilterListType::RegexAllowlist => parse_unknown_lines(contents),
        crate::FilterListType::RegexBlocklist => parse_regex(contents),
        crate::FilterListType::Hostfile => parse_domain_list(contents, false, true),
        crate::FilterListType::DNSRPZ => parse_unknown_lines(contents),
        crate::FilterListType::PrivacyBadger => vec![],
    }
}

#[server]
pub async fn parse_list(url: crate::FilterListUrl) -> Result<(), ServerFnError> {
    log::info!(
        "Parsing {} as format {}",
        url.as_str(),
        url.list_format.as_str()
    );
    let start = std::time::Instant::now();
    let pool = crate::server::get_db().await?;
    let mut tx = pool.begin().await?;
    let url_str = url.as_str();
    let record = sqlx::query!(
        "SELECT id, contents FROM filterLists WHERE url = $1",
        url_str
    )
    .fetch_one(&mut *tx)
    .await?;
    let list_id = record.id;
    let rules = {
        let contents = record.contents;
        parse_list_contents(&contents, url.list_format)
    };
    let (mut domain_src, mut domains, mut allow, mut subdomain) = (vec![], vec![], vec![], vec![]);
    let (mut ip_source, mut ips, mut allow_ips) = (vec![], vec![], vec![]);
    let mut other_rules_src = vec![];
    for rule in rules.iter() {
        let source = rule.get_source().as_ref();
        let source = source[..source.len().min(2000)].to_string();
        match rule.get_rule() {
            crate::list_parser::Rule::Domain(domain_rule) => {
                domain_src.push(source);
                domains.push(domain_rule.domain.as_ref().to_string());
                allow.push(domain_rule.allow);
                subdomain.push(domain_rule.subdomain);
            }
            crate::list_parser::Rule::IpRule(ip_rule) => {
                ip_source.push(source);
                ips.push(ip_rule.ip);
                allow_ips.push(ip_rule.allow);
            }
            _ => {
                other_rules_src.push(source);
            }
        }
    }
    log::info!(
        "Inserting {} rules ({} domain rules, {} IP rules, {} unknown)",
        rules.len(),
        domain_src.len(),
        ip_source.len(),
        other_rules_src.len()
    );
    sqlx::query! {"DELETE FROM list_rules WHERE list_id = $1", list_id}
        .execute(&mut *tx)
        .await?;
    sqlx::query!(
        "INSERT INTO domains (domain)
    SELECT domain FROM UNNEST($1::text[]) AS t(domain) ON CONFLICT DO NOTHING",
        &domains[..]
    )
    .execute(&mut *tx)
    .await?;

    sqlx::query!("INSERT INTO domain_rules (domain_id, allow, subdomain)
    SELECT domains.id, allow, subdomain FROM UNNEST($1::text[], $2::bool[], $3::bool[]) AS t(domain, allow, subdomain)
    INNER JOIN domains ON domains.domain = t.domain
    ON CONFLICT DO NOTHING",
    &domains[..],
    &allow[..],
    &subdomain[..]
    ).execute(&mut *tx).await?;

    sqlx::query!("INSERT INTO Rules (domain_rule_id)
    SELECT domain_rules.id FROM UNNEST($1::text[], $2::bool[], $3::bool[]) AS t(domain, allow, subdomain)
    INNER JOIN domains ON domains.domain = t.domain
    INNER JOIN domain_rules ON domain_rules.domain_id = domains.id AND domain_rules.allow = t.allow AND domain_rules.subdomain = t.subdomain
    ON CONFLICT DO NOTHING",
    &domains[..],
    &allow[..],
    &subdomain[..]
    ).execute(&mut *tx).await?;

    sqlx::query!("INSERT INTO rule_source (source, rule_id)
    SELECT source, Rules.id FROM UNNEST ($1::text[], $2::text[], $3::bool[], $4::bool[]) AS t(source, domain, allow, subdomain)
    INNER JOIN domains ON domains.domain = t.domain
    INNER JOIN domain_rules ON domain_rules.domain_id = domains.id AND domain_rules.allow = t.allow AND domain_rules.subdomain = t.subdomain
    INNER JOIN Rules ON Rules.domain_rule_id = domain_rules.id
    ON CONFLICT DO NOTHING",
    &domain_src[..],
    &domains[..],
    &allow[..],
    &subdomain[..]
    ).execute(&mut *tx).await?;

    sqlx::query!(
        "INSERT INTO ip_rules (ip_network, allow)
    SELECT ip, allow FROM UNNEST($1::inet[], $2::bool[]) AS t(ip, allow)
    ON CONFLICT DO NOTHING",
        &ips[..],
        &allow_ips[..]
    )
    .execute(&mut *tx)
    .await?;

    sqlx::query!(
        "INSERT INTO Rules (ip_rule_id)
    SELECT ip_rules.id FROM UNNEST($1::inet[], $2::bool[]) AS t(ip, allow)
    INNER JOIN ip_rules ON ip_rules.ip_network = t.ip AND ip_rules.allow = t.allow
    ON CONFLICT DO NOTHING
    ",
        &ips[..],
        &allow_ips[..]
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query!(
        "INSERT INTO rule_source (source, rule_id)
    SELECT source, Rules.id FROM UNNEST ($1::text[], $2::inet[], $3::bool[]) AS t(source, ip, allow)
    INNER JOIN ip_rules ON ip_rules.ip_network = t.ip AND ip_rules.allow = t.allow
    INNER JOIN Rules ON Rules.ip_rule_id = ip_rules.id
    ON CONFLICT DO NOTHING",
        &ip_source[..],
        &ips[..],
        &allow_ips[..]
    )
    .execute(&mut *tx)
    .await?;

    sqlx::query!("INSERT INTO list_rules (list_id, source_id)
    SELECT $1, rule_source.id FROM UNNEST ($2::text[], $3::inet[], $4::bool[]) AS t(source, ip, allow)
    INNER JOIN ip_rules ON ip_rules.ip_network = t.ip AND ip_rules.allow = t.allow
    INNER JOIN Rules ON Rules.ip_rule_id = ip_rules.id
    INNER JOIN rule_source ON rule_source.rule_id = Rules.id
    WHERE rule_source.source = t.source
    ",
list_id,
&ip_source[..],
&ips[..],
&allow_ips[..]
).execute(&mut *tx).await?;

    sqlx::query!(
        "INSERT INTO Rules (domain_rule_id, ip_rule_id) VALUES (NULL, NULL)
    ON CONFLICT DO NOTHING",
    )
    .execute(&mut *tx)
    .await?;

    sqlx::query!(
        "INSERT INTO rule_source (source, rule_id)
    SELECT source, Rules.id FROM UNNEST ($1::text[]) AS t(source)
    INNER JOIN Rules ON Rules.domain_rule_id IS NULL AND Rules.ip_rule_id IS NULL
    ON CONFLICT DO NOTHING",
        &other_rules_src[..],
    )
    .execute(&mut *tx)
    .await?;

    sqlx::query!(
        "INSERT INTO list_rules (list_id, source_id)
    SELECT $1, rule_source.id FROM UNNEST($2::text[], $3::text[], $4::bool[], $5::bool[]) AS t(source, domain, allow, subdomain)
    INNER JOIN domains ON domains.domain = t.domain
    INNER JOIN domain_rules ON domain_rules.domain_id = domains.id AND domain_rules.allow = t.allow AND domain_rules.subdomain = t.subdomain
    INNER JOIN Rules ON Rules.domain_rule_id = domain_rules.id
    INNER JOIN rule_source ON rule_source.rule_id = Rules.id
    WHERE rule_source.source = t.source
    ON CONFLICT DO NOTHING",
        list_id,
        &domain_src[..],
        &domains[..],
        &allow[..],
        &subdomain[..]
    ).execute(&mut *tx).await?;

    sqlx::query!(
        "INSERT INTO list_rules (list_id, source_id)
        SELECT $1, rule_source.id FROM UNNEST ($2::text[]) AS t(source)
        INNER JOIN Rules ON Rules.domain_rule_id IS NULL AND Rules.ip_rule_id IS NULL
        INNER JOIN rule_source ON rule_source.rule_id = Rules.id
        WHERE rule_source.source = t.source
        ON CONFLICT DO NOTHING
        ",
        list_id,
        &other_rules_src[..],
    )
    .execute(&mut *tx)
    .await?;
    log::info!("Inserted list rules");

    tx.commit().await?;
    log::info!("Total time: {:?}", start.elapsed());
    Ok(())
}
