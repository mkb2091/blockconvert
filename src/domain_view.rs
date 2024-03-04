use crate::{
    app::Loading,
    rule_view::{DisplayRule, RuleData},
    DomainId, RuleId, SourceId,
};
use leptos::*;
use leptos_router::*;
use std::{collections::BTreeSet, net::IpAddr};

#[server]
async fn get_dns_result(
    domain: String,
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
        domain
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
fn DnsResultView(get_domain: Box<dyn Fn() -> Result<String, ParamsError>>) -> impl IntoView {
    let dns_results = create_resource(get_domain, |domain| async move {
        let results = get_dns_result(domain?).await?;
        Ok::<_, ServerFnError>(results)
    });
    view! {
        <Transition fallback=move || {
            view! { <p>"Loading" <Loading/></p> }
        }>
            {move || match dns_results.get() {
                Some(Ok((ips, cnames))) => {
                    view! {
                        <div>
                            "IP Addresses" <table class="table table-zebra">
                                <For
                                    each=move || { ips.clone() }
                                    key=|ip| *ip
                                    children=|ip| {
                                        let href = format!("/ip/{}", ip);
                                        view! {
                                            <tr>
                                                <td>IP Address</td>
                                                <td>
                                                    <A href=href class="link link-neutral">
                                                        {ip.to_string()}
                                                    </A>
                                                </td>
                                            </tr>
                                        }
                                    }
                                />

                                <For
                                    each=move || { cnames.clone() }
                                    key=|(id, _cname)| *id
                                    children=|(_id, cname)| {
                                        let href = format!("/domain/{}", cname);
                                        view! {
                                            <tr>
                                                <td>CNAME</td>
                                                <td>
                                                    <A href=href class="link link-neutral">
                                                        {cname}
                                                    </A>
                                                </td>
                                            </tr>
                                        }
                                    }
                                />

                            </table>
                        </div>
                    }
                        .into_view()
                }
                _ => view! { <p>"Error"</p> }.into_view(),
            }}

        </Transition>
    }
}

#[server]
async fn get_blocked_by(
    domain: String,
) -> Result<Vec<(String, RuleId, SourceId, crate::list_parser::RulePair)>, ServerFnError> {
    let records = sqlx::query!(
        r#"
        WITH matching_domain_rules AS (
            SELECT domain_rules.id as domain_rule_id, domain_rules.domain_id, allow, subdomain
            FROM domain_rules
            INNER JOIN domains ON domain_rules.domain_id = domains.id
            WHERE domains.domain = $1
        ),
        matching_subdomains_rules AS (
            SELECT domain_rules.id as domain_rule_id, domain_rules.domain_id, allow, subdomain
            FROM domain_rules
            INNER JOIN subdomains ON domain_rules.domain_id = subdomains.parent_domain_id
            INNER JOIN domains ON subdomains.domain_id = domains.id
            WHERE domains.domain = $1 AND domain_rules.subdomain = true
        ),
        combined_matching_domain_rules AS (
            SELECT domain_rule_id, domain_id, allow, subdomain FROM matching_domain_rules
            UNION ALL
            SELECT domain_rule_id, domain_id, allow, subdomain FROM matching_subdomains_rules
        )
        SELECT Rules.id as rule_id,
        domain as "domain: Option<String>", combined_matching_domain_rules.allow as "domain_allow: Option<bool>", subdomain as "subdomain: Option<bool>",
        ip_rules.ip_network as "ip_network: Option<ipnetwork::IpNetwork>", ip_rules.allow as "ip_allow: Option<bool>",
        source_id, source, url
        FROM combined_matching_domain_rules
        INNER JOIN Rules ON combined_matching_domain_rules.domain_rule_id = rules.domain_rule_id
        INNER JOIN rule_source ON rules.id = rule_source.rule_id
        INNER JOIN list_rules ON rule_source.id = list_rules.source_id
        INNER JOIN filterLists ON list_rules.list_id = filterLists.id
        LEFT JOIN domains ON combined_matching_domain_rules.domain_id = domains.id
        LEFT JOIN ip_rules ON rules.ip_rule_id = ip_rules.id
        ORDER BY url
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
                domain_allow: record.domain_allow.flatten(),
                domain_subdomain: record.subdomain.flatten(),
                ip_network: record.ip_network,
                ip_allow: record.ip_allow,
            };
            let rule = rule_data.try_into()?;
            let source = record.source.clone();
            let pair = crate::list_parser::RulePair::new(source.into(), rule);
            let url = record.url.clone();
            Ok((
                url,
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
                                children=|(url, rule_id, source_id, pair)| {
                                    let source = pair.get_source().to_string();
                                    let rule = pair.get_rule().clone();
                                    let rule_href = format!("/rule/{}", rule_id.0);
                                    let source_href = format!("/rule_source/{}", source_id.0);
                                    view! {
                                        <tr>
                                            <td>{url}</td>
                                            <td>
                                                <A href=source_href class="link link-neutral">
                                                    {source}
                                                </A>
                                            </td>
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
                                key=|subdomain| subdomain.clone()
                                children=|subdomain| {
                                    let domain_href = format!("/domain/{}", subdomain);
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
    view! {
        <div>
            {move || {
                let domain = get_domain();
                view! {
                    <h1 class="text-3xl">"Domain: " {domain}</h1>
                    <DnsResultView get_domain=Box::new(get_domain)/>
                    <p>"Blocked by"</p>
                    <BlockedBy get_domain=Box::new(get_domain)/>
                    <p>"Subdomains"</p>
                    <DisplaySubdomains get_domain=Box::new(get_domain)/>
                }
            }}

        </div>
    }
}
