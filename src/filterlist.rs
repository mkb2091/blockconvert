pub use crate::domain::Domain;
use crate::PAGE_SIZE;
use crate::{rule::RuleId, source::SourceId};
use leptos::*;
use leptos::{server, ServerFnError};

use crate::rule::DisplayRule;
#[cfg(feature = "ssr")]
use crate::rule::RuleData;

use leptos_router::*;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::sync::Arc;

#[cfg_attr(feature = "ssr", derive(sqlx::Encode, sqlx::Decode))]
#[derive(Serialize, Deserialize, Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct ListId(i32);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FilterListRecord {
    pub name: Arc<str>,
    pub list_format: FilterListType,
    pub author: Arc<str>,
    pub license: Arc<str>,
    pub expires: std::time::Duration,
    pub last_updated: Option<chrono::DateTime<chrono::Utc>>,
    pub list_size: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, PartialOrd, Eq, Ord, Hash)]
#[serde(transparent)]
pub struct FilterListUrl {
    url: Arc<str>,
}

impl FilterListUrl {
    pub fn as_str(&self) -> &str {
        self.as_ref()
    }
    pub fn to_internal_path(&self) -> Option<std::path::PathBuf> {
        if self.as_str().starts_with("internal/") {
            Some(std::path::PathBuf::from(self.as_str()))
        } else {
            None
        }
    }
}

impl std::ops::Deref for FilterListUrl {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        self.url.as_ref()
    }
}

impl FromStr for FilterListUrl {
    type Err = url::ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "internal/blocklist.txt" | "internal/block_ips.txt" | "internal/allowlist.txt" => {
                Ok(Self { url: s.into() })
            }
            s => Ok(Self {
                url: url::Url::parse(s)?.as_str().into(),
            }),
        }
    }
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FilterListType {
    Adblock,
    DomainBlocklist,
    DomainBlocklistWithoutSubdomains,
    DomainAllowlist,
    IPBlocklist,
    IPAllowlist,
    IPNetBlocklist,
    DenyHosts,
    RegexAllowlist,
    RegexBlocklist,
    Hostfile,
}

impl FilterListType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Adblock => "Adblock",
            Self::DomainBlocklist => "DomainBlocklist",
            Self::DomainBlocklistWithoutSubdomains => "DomainBlocklistWithoutSubdomains",
            Self::DomainAllowlist => "DomainAllowlist",
            Self::IPBlocklist => "IPBlocklist",
            Self::IPAllowlist => "IPAllowlist",
            Self::IPNetBlocklist => "IPNetBlocklist",
            Self::DenyHosts => "DenyHosts",
            Self::RegexAllowlist => "RegexAllowlist",
            Self::RegexBlocklist => "RegexBlocklist",
            Self::Hostfile => "Hostfile",
        }
    }
}
#[derive(Debug, thiserror::Error)]
pub struct InvalidFilterListTypeError;

impl std::fmt::Display for InvalidFilterListTypeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Invalid FilterListType")
    }
}

impl std::str::FromStr for FilterListType {
    type Err = InvalidFilterListTypeError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Adblock" => Ok(Self::Adblock),
            "DomainBlocklist" => Ok(Self::DomainBlocklist),
            "DomainBlocklistWithoutSubdomains" => Ok(Self::DomainBlocklistWithoutSubdomains),
            "DomainAllowlist" => Ok(Self::DomainAllowlist),
            "IPBlocklist" => Ok(Self::IPBlocklist),
            "IPAllowlist" => Ok(Self::IPAllowlist),
            "IPNetBlocklist" => Ok(Self::IPNetBlocklist),
            "DenyHosts" => Ok(Self::DenyHosts),
            "RegexAllowlist" => Ok(Self::RegexAllowlist),
            "RegexBlocklist" => Ok(Self::RegexBlocklist),
            "Hostfile" => Ok(Self::Hostfile),
            _ => Err(InvalidFilterListTypeError),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FilterListMap(
    pub Vec<(FilterListUrl, FilterListRecord)>,
    // Just so it is consistently ordered
);

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

#[cfg(feature = "ssr")]
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

#[cfg(feature = "ssr")]
fn parse_domain_list_line(line: &str, allow: bool, subdomain: bool) -> Option<Rule> {
    let line = line.split('#').next()?;
    if line.is_empty() {
        return None;
    }
    let line = line.trim();
    let mut segments = line.split_whitespace();
    match (segments.next(), segments.next(), segments.next()) {
        (Some(domain), None, None) | (Some("127.0.0.1" | "0.0.0.0"), Some(domain), None) => {
            let (subdomain, domain) = domain
                .strip_prefix("*.")
                .map_or((subdomain, domain), |domain| (true, domain));
            if let Ok(domain) = domain.parse() {
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

#[cfg(feature = "ssr")]
fn parse_domain_list(contents: &str, allow: bool, subdomain: bool) -> Vec<RulePair> {
    parse_lines(contents, &|line| {
        parse_domain_list_line(line, allow, subdomain)
    })
}

#[cfg(feature = "ssr")]
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
                    "3p" | "doc" | "document" | "all" => {
                        match_end_domain = true;
                        block_site = true;
                    }
                    "popup" | "ghide" | "generichide" | "genericblock" | "image" | "script"
                    | "third-party" | "xmlhttprequest" | "stylesheet" | "subdocument" | "media"
                    | "csp" => {
                        has_specific_filters = true;
                    }
                    "important" => {}
                    _ => {
                        has_unknown_tag = true;
                    }
                }
            }
        }
        if has_specific_filters && !block_site {
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
    let (rule, mut match_start_domain, match_exact_start) =
        if let Some(rule) = rule.strip_prefix("||") {
            (rule, true, false)
        } else {
            let (rule, match_exact_start) = rule
                .strip_prefix('|')
                .map_or((rule, false), |rule| (rule, true));
            (rule, false, match_exact_start)
        };

    let (rule, match_end_domain_exact) = rule
        .strip_suffix('|')
        .map_or((rule, false), |rule| (rule, true));
    let (mut rule, match_end_domain) = rule
        .strip_suffix('^')
        .map_or((rule, match_end_domain), |rule| (rule, true));
    if rule.contains('/') {
        return None; // Path selector
    }
    if rule.contains('*') {
        return Some(Rule::Unknown);
    }
    if !match_start_domain {
        (match_start_domain, rule) = rule
            .strip_prefix('.')
            .or_else(|| rule.strip_prefix("*."))
            .map_or((false, rule), |rule| (true, rule));
    }
    if match_start_domain && (match_end_domain | match_end_domain_exact) {
        if let Ok(domain) = rule.parse() {
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

#[cfg(feature = "ssr")]
fn parse_adblock(contents: &str) -> Vec<RulePair> {
    parse_lines(contents, &parse_adblock_line)
}

#[cfg(feature = "ssr")]
fn parse_regex_line(line: &str) -> Option<Rule> {
    if line.starts_with('#') {
        return None;
    }
    if let Some(rule) = line.strip_prefix(r"(^|\.)") {
        if let Some(rule) = rule.strip_suffix('$') {
            let mut rule = rule.to_string();
            rule.retain(|c| c != '/');
            if let Ok(domain) = rule.parse() {
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

#[cfg(feature = "ssr")]
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

#[cfg(feature = "ssr")]
fn parse_ip_network_list(contents: &str, allow: bool) -> Vec<RulePair> {
    parse_lines(contents, &|line| parse_ip_network_line(line, allow))
}

#[cfg(feature = "ssr")]
fn parse_regex(contents: &str) -> Vec<RulePair> {
    parse_lines(contents, &parse_regex_line)
}

#[cfg(feature = "ssr")]
fn parse_unknown_lines(contents: &str) -> Vec<RulePair> {
    parse_lines(contents, &|_| Some(Rule::Unknown))
}

#[cfg(feature = "ssr")]
pub fn parse_list_contents(contents: &str, list_format: FilterListType) -> Vec<RulePair> {
    match list_format {
        FilterListType::Adblock => parse_adblock(contents),
        FilterListType::DomainBlocklist => parse_domain_list(contents, false, true),
        FilterListType::DomainBlocklistWithoutSubdomains => {
            parse_domain_list(contents, false, false)
        }
        FilterListType::DomainAllowlist => parse_domain_list(contents, true, false),
        FilterListType::IPBlocklist => parse_ip_network_list(contents, false),
        FilterListType::IPAllowlist => parse_ip_network_list(contents, true),
        FilterListType::IPNetBlocklist => parse_ip_network_list(contents, false),
        FilterListType::DenyHosts => parse_unknown_lines(contents),
        FilterListType::RegexAllowlist => parse_unknown_lines(contents),
        FilterListType::RegexBlocklist => parse_regex(contents),
        FilterListType::Hostfile => parse_domain_list(contents, false, true),
    }
}

#[server(ParseList)]
pub async fn parse_list(url: FilterListUrl) -> Result<(), ServerFnError> {
    let start = std::time::Instant::now();
    let pool = crate::server::get_db().await?;
    let mut tx = pool.begin().await?;
    let url_str = url.as_str();
    let record = sqlx::query!(
        "SELECT id, format, contents FROM filterLists WHERE url = $1",
        url_str
    )
    .fetch_one(&mut *tx)
    .await?;
    let list_format: FilterListType = record.format.parse()?;

    log::info!(
        "Parsing {} as format {}",
        url.as_str(),
        list_format.as_str()
    );
    let list_id = record.id;
    let rules = {
        let contents = record
            .contents
            .ok_or_else(|| ServerFnError::new("No contents for list"))?;
        parse_list_contents(&contents, list_format)
    };
    let (mut domain_src, mut domains, mut allow, mut subdomain) = (vec![], vec![], vec![], vec![]);
    let (mut ip_source, mut ips, mut allow_ips) = (vec![], vec![], vec![]);
    let mut other_rules_src = vec![];
    for rule in &rules {
        let source = rule.get_source().as_ref();
        let source = source[..source.len().min(2000)].to_string();
        match rule.get_rule() {
            Rule::Domain(domain_rule) => {
                domain_src.push(source);
                domains.push(domain_rule.domain.clone());
                allow.push(domain_rule.allow);
                subdomain.push(domain_rule.subdomain);
            }
            Rule::IpRule(ip_rule) => {
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
        &domains[..] as _
    )
    .execute(&mut *tx)
    .await?;

    sqlx::query!("INSERT INTO domain_rules (domain_id, allow, subdomain)
    SELECT domains.id, allow, subdomain FROM UNNEST($1::text[], $2::bool[], $3::bool[]) AS t(domain, allow, subdomain)
    INNER JOIN domains ON domains.domain = t.domain
    ON CONFLICT DO NOTHING",
    &domains[..] as _,
    &allow[..],
    &subdomain[..]
    ).execute(&mut *tx).await?;

    sqlx::query!("INSERT INTO Rules (domain_rule_id)
    SELECT domain_rules.id FROM UNNEST($1::text[], $2::bool[], $3::bool[]) AS t(domain, allow, subdomain)
    INNER JOIN domains ON domains.domain = t.domain
    INNER JOIN domain_rules ON domain_rules.domain_id = domains.id AND domain_rules.allow = t.allow AND domain_rules.subdomain = t.subdomain
    ON CONFLICT DO NOTHING",
    &domains[..] as _,
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
    &domains[..] as _,
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
    ON CONFLICT DO NOTHING
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
        &domains[..] as _,
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

    sqlx::query!(
        "UPDATE filterLists SET rule_count=$2
    WHERE id = $1",
        list_id,
        rules.len() as i32
    )
    .execute(&mut *tx)
    .await?;

    log::info!("Inserted list rules");

    tx.commit().await?;
    log::info!("Total time: {:?}", start.elapsed());
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CsvRecord {
    pub name: String,
    pub url: FilterListUrl,
    pub author: String,
    pub license: String,
    pub expires: u64,
    pub list_type: FilterListType,
}

#[server]
pub async fn load_filter_map() -> Result<(), ServerFnError> {
    dotenvy::dotenv()?;
    let filterlists_path: std::path::PathBuf = std::env::var("FILTERLISTS_PATH")?.parse()?;
    let contents = tokio::fs::read_to_string(filterlists_path).await?;
    let records = csv::Reader::from_reader(contents.as_bytes())
        .deserialize::<CsvRecord>()
        .collect::<Result<Vec<CsvRecord>, _>>()?;
    let mut urls = Vec::new();
    let mut names = Vec::new();
    let mut formats = Vec::new();
    let mut expires_list = Vec::new();
    let mut authors = Vec::new();
    let mut licenses = Vec::new();

    for csv_record in &records {
        let url = csv_record.url.as_str().to_string();
        let name = csv_record.name.clone();
        let format = csv_record.list_type.as_str().to_string();
        let expires = csv_record.expires as i32;
        let author = csv_record.author.clone();
        let license = csv_record.license.clone();
        urls.push(url);
        names.push(name);
        formats.push(format);
        expires_list.push(expires);
        authors.push(author);
        licenses.push(license);
    }

    let pool = crate::server::get_db().await?;
    sqlx::query!(
        "INSERT INTO filterLists (url, name, format, expires, author, license)
        SELECT * FROM UNNEST($1::text[], $2::text[], $3::text[], $4::int[], $5::text[], $6::text[])
        ON CONFLICT (url) DO UPDATE
        SET name = EXCLUDED.name, format = EXCLUDED.format, expires = EXCLUDED.expires, author = EXCLUDED.author, license = EXCLUDED.license
        ",
        &urls,
        &names,
        &formats,
        &expires_list,
        &authors,
        &licenses
    ).execute(&pool).await?;
    write_filter_map().await?;
    Ok(())
}

#[server]
pub async fn watch_filter_map() -> Result<(), ServerFnError> {
    dotenvy::dotenv()?;
    let filterlists_path: std::path::PathBuf = std::env::var("FILTERLISTS_PATH")?.parse()?;
    use notify::Watcher;
    let notify = std::sync::Arc::new(tokio::sync::Notify::new());
    let notify2 = notify.clone();
    load_filter_map().await?;
    let mut watcher = notify::recommended_watcher(move |_| {
        notify.notify_one();
    })?;
    watcher.watch(&filterlists_path, notify::RecursiveMode::NonRecursive)?;
    let mut last_updated = std::time::Instant::now();
    loop {
        notify2.notified().await;
        if last_updated.elapsed() > std::time::Duration::from_millis(200) {
            load_filter_map().await?;
            last_updated = std::time::Instant::now();
        }
    }
}

#[server]
pub async fn write_filter_map() -> Result<(), ServerFnError> {
    use csv::Writer;
    dotenvy::dotenv()?;
    let filterlists_path: std::path::PathBuf = std::env::var("FILTERLISTS_PATH")?.parse()?;
    let pool = crate::server::get_db().await?;
    let rows = sqlx::query!("SELECT url, name, format, expires, author, license FROM filterLists")
        .fetch_all(&pool)
        .await?;
    let mut records = Vec::new();
    for record in rows {
        records.push(CsvRecord {
            name: record.name.unwrap_or(String::new()),
            url: record.url.parse()?,
            author: record.author.unwrap_or(String::new()),
            license: record.license.unwrap_or(String::new()),
            expires: record.expires as u64,
            list_type: FilterListType::from_str(&record.format)?,
        });
    }
    records.sort_by_key(|record| (record.name.clone(), record.url.clone()));
    records.reverse();
    let mut wtr = Writer::from_path(filterlists_path)?;
    for record in records {
        wtr.serialize(record)?;
    }
    Ok(())
}

#[server]
pub async fn get_filter_map() -> Result<FilterListMap, ServerFnError> {
    let pool = crate::server::get_db().await?;
    let rows = sqlx::query!(
        "SELECT url, name, format, expires, author, license, lastupdated, rule_count
    FROM filterLists"
    )
    .fetch_all(&pool)
    .await?;

    let mut filter_list_map = Vec::new();
    for record in rows {
        let url = record.url.parse()?;
        let record = FilterListRecord {
            name: record.name.unwrap_or(String::new()).into(),
            list_format: FilterListType::from_str(&record.format)?,
            author: record.author.unwrap_or(String::new()).into(),
            license: record.license.unwrap_or(String::new()).into(),
            expires: std::time::Duration::from_secs(record.expires as u64),
            last_updated: record.lastupdated,
            list_size: record.rule_count as usize,
        };
        filter_list_map.push((url, record));
    }

    Ok(FilterListMap(filter_list_map))
}

#[cfg(feature = "ssr")]
struct LastVersionData {
    last_updated: chrono::DateTime<chrono::Utc>,
    etag: Option<String>,
}

#[cfg(feature = "ssr")]
async fn get_last_version_data(
    url: &FilterListUrl,
) -> Result<Option<LastVersionData>, ServerFnError> {
    let pool = crate::server::get_db().await?;
    let url_str = url.as_str();
    #[allow(non_camel_case_types)]
    let last_version_data = sqlx::query!(
        r#"SELECT lastUpdated as "last_updated: chrono::DateTime<chrono::Utc>", etag FROM filterLists WHERE url = $1"#,
        url_str
    )
    .fetch_one(&pool)
    .await
    .ok();
    let last_version_data = last_version_data.and_then(|row| {
        Some(LastVersionData {
            last_updated: row.last_updated?,
            etag: row.etag,
        })
    });
    Ok(last_version_data)
}

#[server]
pub async fn get_last_updated(
    url: FilterListUrl,
) -> Result<Option<chrono::DateTime<chrono::Utc>>, ServerFnError> {
    get_last_version_data(&url)
        .await
        .map(|data| data.map(|data| data.last_updated))
}

#[cfg(feature = "ssr")]
#[derive(thiserror::Error, Debug)]
enum UpdateListError {
    #[error("Failed to fetch list")]
    FailedToFetch,
}

#[server(UpdateListFn)]
pub async fn update_list(url: FilterListUrl) -> Result<(), ServerFnError> {
    let pool = crate::server::get_db().await?;
    let old_contents = sqlx::query!(
        "SELECT contents FROM filterLists WHERE url = $1",
        url.as_str()
    )
    .fetch_one(&pool)
    .await?
    .contents;
    if let Some(internal_path) = url.to_internal_path() {
        let contents = tokio::fs::read_to_string(&internal_path).await?;
        let mut lines = contents.lines().collect::<Vec<_>>();
        lines.sort_unstable();
        lines.dedup();
        let sorted_contents = lines.join("\n");
        tokio::fs::write(internal_path, &sorted_contents).await?;
        let new_last_updated = chrono::Utc::now();
        sqlx::query!(
            "UPDATE filterLists
            SET lastUpdated = $2, contents = $3
            WHERE url = $1
            ",
            url.as_str(),
            new_last_updated,
            sorted_contents
        )
        .execute(&pool)
        .await?;
        if old_contents != Some(sorted_contents) {
            parse_list(url).await?;
        }
        return Ok(());
    }
    log::info!("Updating {}", url.as_str());
    let url_str = url.as_str();
    let last_updated = get_last_version_data(&url).await?;
    let mut req = reqwest::Client::new().get(url_str);
    if let Some(last_updated) = last_updated {
        req = req.header(
            "if-modified-since",
            last_updated
                .last_updated
                .format("%a, %d %b %Y %H:%M:%S GMT")
                .to_string(),
        );
        if let Some(etag) = last_updated.etag {
            req = req.header("if-none-match", etag);
        }
    }
    let response = req.send().await?;
    match response.status() {
        reqwest::StatusCode::NOT_MODIFIED => {
            log::info!("Not modified {:?}", url_str);
            sqlx::query!(
                "UPDATE filterLists
                SET lastUpdated = NOW()
                WHERE url = $1
                ",
                url_str
            )
            .execute(&pool)
            .await?;
            Ok(())
        }
        reqwest::StatusCode::OK => {
            let headers = response.headers().clone();
            let etag = headers.get("etag").and_then(|item| item.to_str().ok());
            let body = response.text().await?;
            log::info!("Updated {} size ({})", url_str, body.len());
            sqlx::query!(
                "UPDATE filterLists
                SET contents = $2, etag = $3
                WHERE url = $1
                ",
                url_str,
                body,
                etag
            )
            .execute(&pool)
            .await?;
            if Some(body) == old_contents {
                log::info!("No change in contents for {}", url_str);
            } else {
                parse_list(url.clone()).await?;
            }
            sqlx::query!(
                "UPDATE filterLists
                SET lastUpdated = NOW()
                WHERE url = $1
                ",
                url_str
            )
            .execute(&pool)
            .await?;
            Ok(())
        }
        status => {
            log::error!("Error fetching {}: {:?}", url_str, status);
            Err(UpdateListError::FailedToFetch.into())
        }
    }
}

#[server(DeleteListFn)]
pub async fn delete_list(url: FilterListUrl) -> Result<(), ServerFnError> {
    let pool = crate::server::get_db().await?;
    let url_str = url.as_str();
    sqlx::query!(
        "DELETE FROM list_rules
    WHERE list_rules.list_id IN (
        SELECT id FROM filterLists WHERE url = $1
    )",
        url_str
    )
    .execute(&pool)
    .await?;
    sqlx::query!("DELETE FROM filterLists WHERE url = $1", url_str)
        .execute(&pool)
        .await?;
    write_filter_map().await?;
    Ok(())
}

#[component]
pub fn FilterListLink(url: FilterListUrl) -> impl IntoView {
    let href = format!(
        "/list{}",
        params_map! {
            "url" => url.as_str(),
        }
        .to_query_string(),
    );
    view! {
        <A href=href class="link link-neutral">
            {url.as_str().to_string()}
        </A>
    }
}

#[server]
async fn get_list_size(url: FilterListUrl) -> Result<Option<usize>, ServerFnError> {
    let pool = crate::server::get_db().await?;
    let url_str = url.as_str();
    let record = sqlx::query!(
        "SELECT id, rule_count FROM filterLists WHERE url = $1",
        url_str
    )
    .fetch_one(&pool)
    .await?;
    let list_id = record.id;
    let count = record.rule_count;
    if count == 0 {
        let count = sqlx::query!(
            "SELECT COUNT(*) FROM list_rules WHERE list_id = $1",
            list_id
        )
        .fetch_one(&pool)
        .await?
        .count;
        if let Some(count) = count {
            sqlx::query!(
                "UPDATE filterLists SET rule_count = $1 WHERE id = $2",
                count as i32,
                list_id
            )
            .execute(&pool)
            .await?;
            Ok(Some(count as usize))
        } else {
            Ok(None)
        }
    } else {
        Ok(Some(count as usize))
    }
}

#[component]
pub fn ListSize(url: FilterListUrl, list_size: Option<usize>) -> impl IntoView {
    if let Some(size) = list_size {
        if size > 0 {
            return size.into_view();
        }
    }
    view! {
        <Await
            future=move || {
                let url = url.clone();
                async { get_list_size(url).await }
            }

            let:size
        >
            {match size {
                Err(err) => format!("{err:?}").into_view(),
                Ok(None) => "Never".into_view(),
                Ok(Some(size)) => size.into_view(),
            }}

        </Await>
    }
    .into_view()
}

#[server]
async fn get_list_page(
    url: FilterListUrl,
    page: Option<usize>,
    page_size: usize,
) -> Result<Vec<(RuleId, SourceId, crate::filterlist::RulePair)>, ServerFnError> {
    let pool = crate::server::get_db().await?;
    let url_str = url.as_str();
    let id = sqlx::query!("SELECT id FROM filterLists WHERE url = $1", url_str)
        .fetch_one(&pool)
        .await?
        .id;
    let start = page.unwrap_or(0) * page_size;
    let records = sqlx::query!(
        r#"SELECT Rules.id AS "rule_id: RuleId", rule_source.id AS "source_id: SourceId", rule_source.source,
        domain as "domain: Option<String>" , domain_rules.allow as "domain_allow: Option<bool>", subdomain as "subdomain: Option<bool>",
        ip_network as "ip_network: Option<ipnetwork::IpNetwork>", ip_rules.allow as "ip_allow: Option<bool>"
        FROM list_rules
        INNER JOIN rule_source ON rule_source.id = list_rules.source_id
        INNER JOIN Rules ON Rules.id = rule_source.rule_id
        LEFT JOIN domain_rules ON domain_rules.id = Rules.domain_rule_id
        LEFT JOIN domains ON domains.id = domain_rules.domain_id
        LEFT JOIN ip_rules ON ip_rules.id = Rules.ip_rule_id
        WHERE list_id = $1
        ORDER BY list_rules.source_id
        LIMIT $2 OFFSET $3
    "#r,
        id,
        page_size as i64 ,
        start as i64
    )
    .fetch_all(&pool)
    .await?;
    let rules = records
        .iter()
        .map(|record| {
            let rule_data = RuleData {
                rule_id: record.rule_id,
                domain: record.domain.clone(),
                domain_allow: record.domain_allow,
                domain_subdomain: record.subdomain,
                ip_network: record.ip_network,
                ip_allow: record.ip_allow,
            };
            let rule = rule_data.try_into()?;
            let source = record.source.clone();
            let pair = crate::filterlist::RulePair::new(source.into(), rule);
            Ok((record.rule_id, record.source_id, pair))
        })
        .collect::<Result<Vec<(_, _, _)>, ServerFnError>>();

    rules
}

#[component]
fn LastUpdatedInner(last_updated: Option<chrono::DateTime<chrono::Utc>>) -> impl IntoView {
    view! {
        {match last_updated {
            Some(last_updated) => {
                view! { <div>{format!("{last_updated}")}</div> }
            }
            None => {
                view! { <div>"Never"</div> }
            }
        }}
    }
}

#[component]
pub fn LastUpdated(url: FilterListUrl, record: Option<FilterListRecord>) -> impl IntoView {
    view! {
        {match record.clone() {
            Some(record) => {
                let last_updated = record.last_updated;
                view! { <LastUpdatedInner last_updated=last_updated/> }
            }
            None => {
                view! {
                    <Await
                        future={
                            let url = url.clone();
                            move || {
                                let url = url.clone();
                                async move {
                                    crate::filterlist::get_last_updated(url.clone()).await
                                }
                            }
                        }

                        let:last_version_data
                    >
                        {match last_version_data {
                            Ok(last_updated) => {
                                view! { <LastUpdatedInner last_updated=*last_updated/> }.into_view()
                            }
                            Err(err) => view! { {format!("{err:?}")} }.into_view(),
                        }}

                    </Await>
                }
            }
        }}

        <FilterListUpdate url=url.clone()/>
    }
}

#[component]
pub fn ParseList(url: FilterListUrl) -> impl IntoView {
    let parse_list_action = create_server_action::<crate::filterlist::ParseList>();
    view! {
        <ActionForm action=parse_list_action>
            <button class="btn btn-primary" type="submit">
                <input type="hidden" placeholder="url" id="url" name="url" value=url.to_string()/>
                "Parse"
            </button>
        </ActionForm>
    }
}

#[component]
pub fn FilterListUpdate(url: FilterListUrl) -> impl IntoView {
    let update_list_action = create_server_action::<UpdateListFn>();
    view! {
        <ActionForm action=update_list_action>
            <button class="btn btn-primary" type="submit">
                <input type="hidden" placeholder="url" id="url" name="url" value=url.to_string()/>
                "Update"
            </button>
        </ActionForm>
    }
}

#[component]
fn Contents(url: FilterListUrl, page: Option<usize>) -> impl IntoView {
    view! {
        <table class="table table-zebra">
            <thead>
                <tr>
                    <th>Source</th>
                    <th>Rule</th>
                </tr>
            </thead>
            <Await
                future=move || {
                    let url = url.clone();
                    async move { get_list_page(url, page, PAGE_SIZE).await }
                }

                let:contents
            >

                {
                    let contents = contents.clone();
                    move || match contents.clone() {
                        Ok(contents) => {
                            let contents = contents.clone();
                            view! {
                                <tbody>
                                    <For
                                        each=move || { contents.clone() }

                                        key=|(rule_id, source_id, _)| (*rule_id, *source_id)
                                        children=|(rule_id, _source_id, pair)| {
                                            let source = pair.get_source().to_string();
                                            let rule = pair.get_rule().clone();
                                            view! {
                                                <tr>
                                                    <td>{source}</td>
                                                    <td>
                                                        <A href=rule_id.get_href() class="link link-neutral">
                                                            <DisplayRule rule=rule/>
                                                        </A>
                                                    </td>
                                                </tr>
                                            }
                                        }
                                    />

                                </tbody>
                            }
                                .into_view()
                        }
                        Err(err) => format!("{err:?}").into_view(),
                    }
                }

            </Await>

        </table>
    }
}

#[component]
fn FilterListInner(url: FilterListUrl, page: Option<usize>) -> impl IntoView {
    view! {
        <h1>"Filter List"</h1>
        <p>"URL: " {url.to_string()}</p>
        <p>"Last Updated: " <LastUpdated url=url.clone() record=None/></p>
        <p>"Rule count: " <ListSize url=url.clone() list_size=None/></p>
        <FilterListUpdate url=url.clone()/>
        <p>
            <ParseList url=url.clone()/>
        </p>

        <DeleteListButton url=url.clone()/>
        {if let Some(page) = page {
            view! { <p>"Page: " {page}</p> }
        } else {
            view! { <p>"Page: 0"</p> }
        }}

        {match page {
            None | Some(0) => view! {}.into_view(),
            Some(page) => {
                let params = params_map! {
                    "url" => url.as_str(), "page" => (page.saturating_sub(1)).to_string()
                };
                let href = format!("/list{}", params.to_query_string());
                view! {
                    <A href=href class="btn btn-neutral">
                        "Back"
                    </A>
                }
            }
        }}

        {
            let params = params_map! {
                "url" => url.as_str(), "page" => (page.unwrap_or(0) + 1).to_string()
            };
            let href = format!("/list{}", params.to_query_string());
            view! {
                <A href=href class="btn btn-neutral">
                    "Next"
                </A>
            }
        }

        <p>"Contents: " <Contents url=url.clone() page=page/></p>
    }
}

#[derive(Params, PartialEq, Debug)]
struct ViewListParams {
    url: Option<String>,
    page: Option<usize>,
}

#[derive(thiserror::Error, Debug)]
enum ViewListError {
    #[error("Invalid URL")]
    ParseURL(#[from] url::ParseError),
    #[error("Invalid URL")]
    ParseParam(#[from] leptos_router::ParamsError),
    #[error("Invalid FilterListType")]
    InvalidFilterListType(#[from] InvalidFilterListTypeError),
}

impl ViewListParams {
    fn parse(&self) -> Result<FilterListUrl, ViewListError> {
        Ok(self
            .url
            .as_ref()
            .ok_or_else(|| ParamsError::MissingParam("Missing Param".into()))?
            .parse()?)
    }
}

#[component]
fn DeleteListButton(url: FilterListUrl) -> impl IntoView {
    let delete_list_action = create_server_action::<DeleteListFn>();
    view! {
        <ActionForm action=delete_list_action>
            <button class="btn btn-danger" type="submit">
                <input type="hidden" placeholder="url" id="url" name="url" value=url.to_string()/>
                "Delete"
            </button>
        </ActionForm>
    }
}

#[component]
pub fn FilterListPage() -> impl IntoView {
    let params = use_query::<ViewListParams>();
    let get_url = move || {
        params.with(|param| {
            param
                .as_ref()
                .ok()
                .map(|param| param.parse().map(|url| (url, param.page)))
        })
    };
    view! {
        <div>

            {move || match get_url() {
                None => view! { <p>"No URL"</p> }.into_view(),
                Some(Err(err)) => view! { <p>"Error: " {format!("{err}")}</p> }.into_view(),
                Some(Ok((url, page))) => view! { <FilterListInner url=url page=page/> }.into_view(),
            }}

        </div>
    }
}
