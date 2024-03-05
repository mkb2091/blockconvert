use crate::app::Loading;
use crate::list_parser::DomainRule;
use crate::list_parser::Rule;
use crate::list_view::FilterListLink;
use crate::FilterListUrl;
use crate::{DomainId, ListId, RuleId, SourceId};
use leptos::*;
use leptos_router::*;
use serde::{Deserialize, Serialize};

#[derive(Params, PartialEq)]
struct RuleParam {
    id: i32,
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
            domain: record.domain.as_str().try_into()?,
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
        Ok(Rule::IpRule(crate::list_parser::IpRule {
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
        "SELECT rule_source.id as source_id, source, filterLists.id as list_id, filterLists.url FROM rule_source
        INNER JOIN list_rules ON rule_source.id = list_rules.source_id
        INNER JOIN filterLists ON list_rules.list_id = filterLists.id
        WHERE rule_id = $1
        ORDER BY (source)
        ",
        id.0
    )
    .fetch_all(&crate::server::get_db().await?)
    .await?;
    sources
        .into_iter()
        .map(|record| {
            Ok((
                SourceId(record.source_id),
                record.source,
                ListId(record.list_id),
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
                                        key=|(id, _, _, _)| *id
                                        children=|(source_id, source, _list_id, url)| {
                                            let source_href = format!("/rule_source/{}", source_id.0);
                                            view! {
                                                <tr>
                                                    <td>
                                                        <A href=source_href class="link link-neutral">
                                                            {source}
                                                        </A>
                                                    </td>
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
                Some(Err(err)) => view! { <p>"Error: " {format!("{}", err)}</p> }.into_view(),
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
            Rule::Unknown => view! { "Unknown" }.into_view(),
            Rule::Invalid => view! { "Invalid Rule" }.into_view(),
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
                Some(Ok(rule)) => {
                    view! {
                        <p>
                            <DisplayRule rule=rule/>

                        </p>
                    }
                        .into_view()
                }
                Some(Err(err)) => view! { <p>"Error: " {format!("{}", err)}</p> }.into_view(),
                None => view! { "Invalid URL" }.into_view(),
            }}

        </Transition>
    }
}

#[server]
async fn get_rule_blocked_domains(id: RuleId) -> Result<Vec<(DomainId, String)>, ServerFnError> {
    let domains = sqlx::query!(
        r#"SELECT DISTINCT domains.id, domain
        FROM Rules
        LEFT JOIN domain_rules ON Rules.domain_rule_id = domain_rules.id
        LEFT JOIN subdomains ON domain_rules.domain_id = subdomains.parent_domain_id AND domain_rules.subdomain = true
        LEFT JOIN domains ON domain_rules.domain_id = domains.id OR subdomains.domain_id = domains.id
        WHERE Rules.id = $1"#r,
        id.0
    )
    .fetch_all(&crate::server::get_db().await?)
    .await?;
    Ok(domains
        .into_iter()
        .map(|record| (DomainId(record.id), record.domain))
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
                            "Blocked Domains:" <table class="table table-zebra">
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
                Some(Err(err)) => view! { <p>"Error: " {format!("{}", err)}</p> }.into_view(),
                None => view! { "Invalid URL" }.into_view(),
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
                    domain: domain.as_str().try_into()?,
                    allow,
                    subdomain,
                }))
            }
            (None, None, None, Some(ip_network), Some(allow)) => {
                Ok(Rule::IpRule(crate::list_parser::IpRule {
                    ip: ip_network,
                    allow,
                }))
            }
            _ => Ok(Rule::Invalid),
        }
    }
}

#[component]
pub fn RuleViewPage() -> impl IntoView {
    let params = use_params::<RuleParam>();
    let get_id = move || {
        params.with(|param| {
            param
                .as_ref()
                .map(|param| RuleId(param.id))
                .map_err(Clone::clone)
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
