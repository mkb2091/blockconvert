use crate::app::Loading;
use crate::filterlist::DomainRule;
use crate::filterlist::FilterListLink;
use crate::filterlist::FilterListUrl;
use crate::filterlist::Rule;
use crate::{domain::DomainId, filterlist::ListId, source::SourceId};
use leptos::*;
use leptos_router::*;
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "ssr", derive(sqlx::Encode, sqlx::Decode))]
#[derive(Serialize, Deserialize, Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct RuleId(i32);

impl RuleId {
    pub fn get_href(&self) -> String {
        format!("/rule/{}", self.0)
    }
}

#[cfg(feature = "ssr")]
pub async fn find_rule_matches() -> Result<(), ServerFnError> {
    use std::time::Duration;

    dotenvy::dotenv()?;
    let pool = crate::server::get_db().await?;
    let read_limit = std::env::var("READ_LIMIT")?.parse::<u32>()? as i64;
    let interval: u64 = std::env::var("RULE_MATCH_CHECK_INTERVAL")?.parse()?;
    let interval: Duration = Duration::from_secs(interval);
    let mut interval = tokio::time::interval(interval);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        let mut tx = pool.begin().await?;
        let records = sqlx::query!(
            "SELECT id from Rules
            ORDER BY last_checked_matches ASC NULLS FIRST
            LIMIT $1",
            read_limit
        )
        .fetch_all(&mut *tx)
        .await?;

        let rule_ids = records
            .into_iter()
            .map(|record| record.id)
            .collect::<Vec<_>>();

        sqlx::query!(
            "DELETE FROM rule_matches WHERE rule_id = ANY($1::int[])",
            &rule_ids[..]
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query!("
            INSERT INTO rule_matches(rule_id, domain_id)
            SELECT Rules.id AS rule_id, domains.id AS domain_id
            FROM Rules
            LEFT JOIN domain_rules ON Rules.domain_rule_id = domain_rules.id
            LEFT JOIN subdomains ON domain_rules.domain_id = subdomains.parent_domain_id AND domain_rules.subdomain = true
            LEFT JOIN ip_rules ON Rules.ip_rule_id = ip_rules.id AND ip_rules.allow=false
            LEFT JOIN dns_ips ON ip_rules.ip_network = dns_ips.ip_address
            LEFT JOIN dns_cnames ON (dns_cnames.cname_domain_id = domain_rules.domain_id
                OR dns_cnames.cname_domain_id = subdomains.domain_id) AND domain_rules.allow=false
            INNER JOIN domains ON domain_rules.domain_id = domains.id
                OR subdomains.domain_id = domains.id
                OR dns_ips.domain_id = domains.id
                OR dns_cnames.domain_id = domains.id
            INNER JOIN dns_ips AS dns_check ON dns_check.domain_id = domains.id AND dns_check.ip_address IS NOT NULL
            WHERE Rules.id = ANY($1::int[])
            ON CONFLICT DO NOTHING
            ",
        &rule_ids[..]).execute(&mut *tx).await?;
        let count = sqlx::query!(
            "SELECT COUNT(*) FROM rule_matches WHERE rule_id = ANY($1::int[])",
            &rule_ids[..]
        )
        .fetch_one(&mut *tx)
        .await?
        .count
        .unwrap_or(0);
        log::info!(
            "Checked {} rules and found {} matches",
            rule_ids.len(),
            count
        );
        sqlx::query!(
            "UPDATE rules
        SET last_checked_matches = now()
        WHERE id = ANY($1::int[])",
            &rule_ids[..]
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
    }
}

#[server]
pub async fn get_rule(id: RuleId) -> Result<Rule, ServerFnError> {
    let record = sqlx::query!(
        "SELECT domain_rule_id, ip_rule_id FROM Rules
        WHERE Rules.id = $1",
        id.0
    )
    .fetch_one(&crate::server::get_db().await?)
    .await?;
    if let Some(domain_rule_id) = record.domain_rule_id {
        let record = sqlx::query!(
            "SELECT domain, allow, subdomain FROM domain_rules
            INNER JOIN domains ON domains.id = domain_rules.domain_id         
            WHERE domain_rules.id = $1",
            domain_rule_id
        )
        .fetch_one(&crate::server::get_db().await?)
        .await?;
        let domain_rule = DomainRule {
            domain: record.domain.parse()?,
            allow: record.allow,
            subdomain: record.subdomain,
        };
        Ok(Rule::Domain(domain_rule))
    } else if let Some(ip_rule_id) = record.ip_rule_id {
        let record = sqlx::query!(
            "SELECT ip_network, allow FROM ip_rules WHERE id = $1",
            ip_rule_id
        )
        .fetch_one(&crate::server::get_db().await?)
        .await?;
        Ok(Rule::IpRule(crate::filterlist::IpRule {
            ip: record.ip_network,
            allow: record.allow,
        }))
    } else {
        Ok(Rule::Invalid)
    }
}

type GetId = Box<dyn Fn() -> Result<RuleId, ParamsError>>;

#[server]
async fn get_sources(
    id: RuleId,
) -> Result<Vec<(SourceId, String, ListId, FilterListUrl)>, ServerFnError> {
    let sources = sqlx::query!(
        r#"SELECT rule_source.id AS "source_id: SourceId", source, filterLists.id as "list_id: ListId", filterLists.url FROM rule_source
        INNER JOIN list_rules ON rule_source.id = list_rules.source_id
        INNER JOIN filterLists ON list_rules.list_id = filterLists.id
        WHERE rule_id = $1
        ORDER BY (source)
        "#r,
        id.0
    )
    .fetch_all(&crate::server::get_db().await?)
    .await?;
    sources
        .into_iter()
        .map(|record| {
            Ok((
                record.source_id,
                record.source,
                record.list_id,
                record.url.parse()?,
            ))
        })
        .collect()
}

#[component]
fn Sources(get_id: GetId) -> impl IntoView {
    let source_resource = create_resource(get_id, |id| async move {
        let sources = get_sources(id?).await?;
        Ok::<_, ServerFnError>(sources)
    });
    view! {
        <Transition fallback=move || {
            view! { <p>"Loading" <Loading/></p> }
        }>
            {move || match source_resource.get() {
                Some(Ok(sources)) => {
                    view! {
                        <p>
                            "Sources:" <table class="table table-zebra">
                                <thead>
                                    <tr>
                                        <th>Source</th>
                                        <th>List</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <For
                                        each=move || { sources.clone() }
                                        key=|(source_id, _, _, _)| *source_id
                                        children=|(_, source, _list_id, url)| {
                                            view! {
                                                <tr>
                                                    <td>{source}</td>
                                                    <td>
                                                        <FilterListLink url=url/>
                                                    </td>
                                                </tr>
                                            }
                                        }
                                    />

                                </tbody>
                            </table>

                        </p>
                    }
                        .into_view()
                }
                Some(Err(err)) => view! { <p>"Error: " {format!("{err}")}</p> }.into_view(),
                None => view! { "Invalid URL" }.into_view(),
            }}

        </Transition>
    }
}

#[component]
pub fn DisplayRule(rule: Rule) -> impl IntoView {
    view! {
        {match rule {
            Rule::Domain(domain_rule) => {
                view! {
                    {if domain_rule.allow { "ALLOW: " } else { "BLOCK: " }}
                    {if domain_rule.subdomain { "*." } else { "" }}
                    {domain_rule.domain.as_ref().to_owned()}
                }
                    .into_view()
            }
            Rule::IpRule(ip_rule) => {
                view! {
                    {if ip_rule.allow { "ALLOW: " } else { "BLOCK: " }}
                    {ip_rule.ip.to_string()}
                }
                    .into_view()
            }
            Rule::Unknown => "Unknown".into_view(),
            Rule::Invalid => "Invalid Rule".into_view(),
        }}
    }
}

#[component]
fn RuleRawView(
    rule: Resource<Result<RuleId, ParamsError>, Result<Rule, ServerFnError>>,
) -> impl IntoView {
    view! {
        <Transition fallback=move || {
            view! { <p>"Loading" <Loading/></p> }
        }>
            {move || match rule.get() {
                Some(Ok(rule)) => view! { <DisplayRule rule=rule/> }.into_view(),
                Some(Err(err)) => view! { <p>"Error: " {format!("{err}")}</p> }.into_view(),
                None => view! { "Invalid URL" }.into_view(),
            }}

        </Transition>
    }
}

#[server]
async fn get_rule_blocked_domains(id: RuleId) -> Result<Vec<(DomainId, String)>, ServerFnError> {
    let domains = sqlx::query!(
        r#"SELECT DISTINCT domains.id as "domain_id: DomainId", domain as "domain: String"
        FROM Rules
        INNER JOIN rule_matches ON Rules.id = rule_matches.rule_id
        INNER JOIN domains ON rule_matches.domain_id = domains.id
        WHERE Rules.id = $1"#r,
        id.0
    )
    .fetch_all(&crate::server::get_db().await?)
    .await?;
    Ok(domains
        .into_iter()
        .map(|record| (record.domain_id, record.domain))
        .collect())
}

#[component]
fn RuleBlockedDomainsView(get_id: Box<dyn Fn() -> Result<RuleId, ParamsError>>) -> impl IntoView {
    let domains_resource = create_resource(get_id, |id| async move {
        let domains = get_rule_blocked_domains(id?).await?;
        Ok::<_, ServerFnError>(domains)
    });
    view! {
        <Transition fallback=move || {
            view! { <p>"Loading" <Loading/></p> }
        }>
            {move || match domains_resource.get() {
                Some(Ok(domains)) => {
                    view! {
                        <p>
                            "Matched Domains:" <table class="table table-zebra">
                                <thead>
                                    <tr>
                                        <th>Domain</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <For
                                        each=move || { domains.clone() }
                                        key=|(id, _)| *id
                                        children=|(_domain_id, domain)| {
                                            let domain_href = format!("/domain/{domain}");
                                            view! {
                                                <tr>
                                                    <td>
                                                        <A href=domain_href class="link link-neutral">
                                                            {domain}
                                                        </A>
                                                    </td>
                                                </tr>
                                            }
                                        }
                                    />

                                </tbody>
                            </table>

                        </p>
                    }
                        .into_view()
                }
                Some(Err(err)) => view! { <p>"Error: " {format!("{err}")}</p> }.into_view(),
                None => "Invalid URL".into_view(),
            }}

        </Transition>
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct RuleData {
    pub rule_id: RuleId,
    pub domain: Option<String>,
    pub domain_allow: Option<bool>,
    pub domain_subdomain: Option<bool>,
    pub ip_network: Option<ipnetwork::IpNetwork>,
    pub ip_allow: Option<bool>,
}

impl TryInto<Rule> for RuleData {
    type Error = ServerFnError;
    fn try_into(self) -> Result<Rule, Self::Error> {
        match (
            self.domain,
            self.domain_allow,
            self.domain_subdomain,
            self.ip_network,
            self.ip_allow,
        ) {
            (Some(domain), Some(allow), Some(subdomain), None, None) => {
                Ok(Rule::Domain(DomainRule {
                    domain: domain.parse()?,
                    allow,
                    subdomain,
                }))
            }
            (None, None, None, Some(ip_network), Some(allow)) => {
                Ok(Rule::IpRule(crate::filterlist::IpRule {
                    ip: ip_network,
                    allow,
                }))
            }
            _ => Ok(Rule::Invalid),
        }
    }
}

#[derive(Params, PartialEq)]
struct RuleParam {
    id: Option<i32>,
}

#[component]
pub fn RuleViewPage() -> impl IntoView {
    let params = use_params::<RuleParam>();
    let get_id = move || {
        params.with(|param| {
            param.as_ref().map_err(Clone::clone).and_then(|param| {
                Ok(RuleId(param.id.ok_or_else(|| {
                    ParamsError::MissingParam("No id".into())
                })?))
            })
        })
    };
    let rule_resource = create_resource(get_id, |id| async move {
        let rule = get_rule(id?).await?;
        Ok::<_, ServerFnError>(rule)
    });
    view! {
        <p>"Rule: " <RuleRawView rule=rule_resource/></p>
        <Sources get_id=Box::new(get_id)/>
        <RuleBlockedDomainsView get_id=Box::new(get_id)/>
    }
}
