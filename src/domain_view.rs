use crate::{
    app::Loading,
    list_parser::Domain,
    list_view::FilterListLink,
    rule_view::{DisplayRule, RuleData},
    DomainId, FilterListUrl, RuleId, SourceId,
};
use leptos::*;
use leptos_router::*;
use std::{collections::BTreeSet, net::IpAddr};

#[server]
async fn get_dns_result(
    domain: Domain,
) -> Result<(BTreeSet<IpAddr>, BTreeSet<(DomainId, String)>), ServerFnError> {
    let records = sqlx::query!(
        r#"SELECT dns_ips.ip_address as "ip_address: Option<ipnetwork::IpNetwork>",
        cname_domains.id as "cname_domain_id: Option<i64>",
        cname_domains.domain as "cname_domain: Option<String>"
    FROM domains
    LEFT JOIN dns_ips ON dns_ips.domain_id=domains.id
    LEFT JOIN dns_cnames on dns_cnames.domain_id=domains.id
    LEFT JOIN domains AS cname_domains ON cname_domains.id=dns_cnames.cname_domain_id
    WHERE domains.domain = $1
    "#r,
        domain.as_ref().to_string()
    )
    .fetch_all(&crate::server::get_db().await?)
    .await?;
    let mut ip_addresses = BTreeSet::new();
    let mut cnames = BTreeSet::new();
    for record in records {
        if let Some(ip) = record.ip_address {
            ip_addresses.insert(ip.ip());
        }
        if let (Some(id), Some(cname)) = (record.cname_domain_id, record.cname_domain) {
            cnames.insert((DomainId(id), cname));
        }
    }
    Ok((ip_addresses, cnames))
}

#[component]
fn DnsResultView(domain: Domain) -> impl IntoView {
    view! {
        <Await
            future=move || {
                let domain = domain.clone();
                async move { get_dns_result(domain.clone()).await }
            }

            let:dns_results
        >

            {
                let dns_results = dns_results.clone();
                move || match dns_results.clone() {
                    Ok((ips, cnames)) => {
                        view! {
                            <div class="grid grid-cols-2 gap-4">
                                <div>
                                    <h2 class="mb-2 text-lg font-bold">IP Addresses</h2>
                                    <ul>
                                        <For
                                            each=move || { ips.clone() }
                                            key=|ip| *ip
                                            children=|ip| {
                                                let href = format!("/ip/{ip}");
                                                view! {
                                                    <li>
                                                        <A href=href class="link link-neutral">
                                                            {ip.to_string()}
                                                        </A>
                                                    </li>
                                                }
                                            }
                                        />

                                    </ul>
                                </div>
                                <div>
                                    <h2 class="mb-2 text-lg font-bold">CNAMEs</h2>
                                    <ul>
                                        <For
                                            each=move || { cnames.clone() }
                                            key=|(id, _cname)| *id
                                            children=|(_id, cname)| {
                                                let href = format!("/domain/{cname}");
                                                view! {
                                                    <li>
                                                        <A href=href class="link link-neutral">
                                                            {cname}
                                                        </A>
                                                    </li>
                                                }
                                            }
                                        />

                                    </ul>

                                </div>

                            </div>
                        }
                            .into_view()
                    }
                    _ => view! { <p>"Error"</p> }.into_view(),
                }
            }

        </Await>
    }
}

#[server]
async fn get_blocked_by(
    domain: String,
) -> Result<
    Vec<(
        FilterListUrl,
        RuleId,
        SourceId,
        crate::list_parser::RulePair,
    )>,
    ServerFnError,
> {
    let records = sqlx::query!(
        r#"
        SELECT Rules.id as rule_id,
        domain_rules_domain.domain as "domain: Option<String>", domain_rules.allow as "domain_allow: Option<bool>", subdomain as "subdomain: Option<bool>",
        ip_rules.ip_network as "ip_network: Option<ipnetwork::IpNetwork>", ip_rules.allow as "ip_allow: Option<bool>",
        source_id, source, url
        FROM domains
        INNER JOIN rule_matches ON domains.id = rule_matches.domain_id
        INNER JOIN Rules on Rules.id = rule_matches.rule_id
        INNER JOIN rule_source ON rules.id = rule_source.rule_id
        INNER JOIN list_rules ON rule_source.id = list_rules.source_id
        INNER JOIN filterLists ON list_rules.list_id = filterLists.id
        LEFT JOIN domain_rules ON rules.domain_rule_id = domain_rules.id
        LEFT JOIN domains AS domain_rules_domain ON domain_rules_domain.id = domain_rules.domain_id
        LEFT JOIN ip_rules ON rules.ip_rule_id = ip_rules.id
        WHERE domains.domain = $1
        ORDER BY url
        LIMIT 100
        "#r,
        domain
    )
    .fetch_all(&crate::server::get_db().await?)
    .await?;
    let rules = records
        .into_iter()
        .map(|record| {
            let rule_data = RuleData {
                rule_id: RuleId(record.rule_id),
                domain: record.domain.clone(),
                domain_allow: record.domain_allow,
                domain_subdomain: record.subdomain,
                ip_network: record.ip_network,
                ip_allow: record.ip_allow,
            };
            let rule = rule_data.try_into()?;
            let source = record.source.clone();
            let pair = crate::list_parser::RulePair::new(source.into(), rule);
            let url = record.url.clone();
            Ok((
                url.parse()?,
                RuleId(record.rule_id),
                SourceId(record.source_id),
                pair,
            ))
        })
        .collect::<Result<Vec<_>, ServerFnError>>()?;

    Ok(rules)
}

#[component]
fn BlockedBy(get_domain: Box<dyn Fn() -> Result<String, ParamsError>>) -> impl IntoView {
    let blocked_by = create_resource(get_domain, |domain| async move {
        let rules = get_blocked_by(domain?).await?;
        Ok::<_, ServerFnError>(rules)
    });
    view! {
        <Transition fallback=move || {
            view! { <p>"Loading" <Loading/></p> }
        }>
            {move || match blocked_by.get() {
                Some(Ok(rules)) => {
                    view! {
                        <table class="table table-zebra">
                            <For
                                each=move || { rules.clone() }
                                key=|(_url, rule_id, source_id, _pair)| (*rule_id, *source_id)
                                children=|(url, rule_id, _source_id, pair)| {
                                    let source = pair.get_source().to_string();
                                    let rule = pair.get_rule().clone();
                                    let rule_href = format!("/rule/{}", rule_id.0);
                                    view! {
                                        <tr>
                                            <td>
                                                <FilterListLink url=url/>
                                            </td>
                                            <td>{source}</td>
                                            <td>
                                                <A href=rule_href class="link link-neutral">
                                                    <DisplayRule rule=rule/>
                                                </A>
                                            </td>
                                        </tr>
                                    }
                                }
                            />

                        </table>
                    }
                        .into_view()
                }
                _ => view! { <p>"Error"</p> }.into_view(),
            }}

        </Transition>
    }
}

#[server]
async fn get_subdomains(domain: String) -> Result<Vec<String>, ServerFnError> {
    let records = sqlx::query!(
        "SELECT subdomain_text.domain
        FROM domains
        INNER JOIN subdomains ON domains.id = subdomains.parent_domain_id
        INNER JOIN domains AS subdomain_text ON subdomains.domain_id = subdomain_text.id
        WHERE domains.domain = $1
        ",
        domain
    )
    .fetch_all(&crate::server::get_db().await?)
    .await?;
    let subdomains = records.into_iter().map(|record| record.domain).collect();
    Ok(subdomains)
}

#[component]
fn DisplaySubdomains(get_domain: Box<dyn Fn() -> Result<String, ParamsError>>) -> impl IntoView {
    let subdomains = create_resource(get_domain, |domain| async move {
        let subdomains = get_subdomains(domain?).await?;
        Ok::<_, ServerFnError>(subdomains)
    });
    view! {
        <Transition fallback=move || {
            view! { <p>"Loading" <Loading/></p> }
        }>
            {move || match subdomains.get() {
                Some(Ok(subdomains)) => {
                    view! {
                        <table class="table table-zebra">
                            <For
                                each=move || { subdomains.clone() }
                                key=std::clone::Clone::clone
                                children=|subdomain| {
                                    let domain_href = format!("/domain/{subdomain}");
                                    view! {
                                        <tr>
                                            <td>
                                                <A href=domain_href class="link link-neutral">
                                                    {subdomain}
                                                </A>
                                            </td>
                                        </tr>
                                    }
                                }
                            />

                        </table>
                    }
                        .into_view()
                }
                _ => view! { <p>"Error"</p> }.into_view(),
            }}

        </Transition>
    }
}

#[derive(Params, PartialEq)]
struct DomainParam {
    domain: String,
}

#[component]
pub fn DomainViewPage() -> impl IntoView {
    let params = use_params::<DomainParam>();
    let get_domain = move || {
        params.with(|param| {
            param
                .as_ref()
                .map(|param| param.domain.clone())
                .map_err(Clone::clone)
        })
    };
    let get_domain_parsed = move || {
        params.with(|param| Ok::<_, ServerFnError>(param.as_ref()?.domain.parse::<Domain>()?))
    };
    view! {
        <div>
            {move || {
                let domain = get_domain_parsed();
                match domain {
                    Ok(domain) => {
                        view! {
                            <h1 class="text-3xl">"Domain: " {domain.as_ref().to_string()}</h1>
                            <DnsResultView domain=domain.clone()/>
                            <p>"Filtered by"</p>
                            <BlockedBy get_domain=Box::new(get_domain)/>
                            <p>"Subdomains"</p>
                            <DisplaySubdomains get_domain=Box::new(get_domain)/>
                        }
                            .into_view()
                    }
                    Err(err) => view! { <p>"Error: " {format!("{err:?}")}</p> }.into_view(),
                }
            }}

        </div>
    }
}
