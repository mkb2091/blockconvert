use leptos::*;

#[server]
async fn count_total_rules() -> Result<usize, ServerFnError> {
    let pool = crate::server::get_db().await?;
    let count = sqlx::query!(
        "SELECT reltuples::bigint AS count
    FROM pg_catalog.pg_class
    WHERE relname = 'rules'"
    )
    .fetch_one(&pool)
    .await?
    .count
    .ok_or_else(|| ServerFnError::new("No count"))? as usize;
    Ok(count)
}

#[component]
fn TotalRuleCount() -> impl IntoView {
    view! {
        <Await future=|| async { count_total_rules().await } let:total_rules>
            {match total_rules {
                Ok(count) => view! { {count} }.into_view(),
                Err(err) => view! { {format!("{err:?}")} }.into_view(),
            }}

        </Await>
    }
}

#[server]
async fn get_total_rule_matches() -> Result<usize, ServerFnError> {
    let pool = crate::server::get_db().await?;
    let count = sqlx::query!(
        "SELECT reltuples::bigint AS count
    FROM pg_catalog.pg_class
    WHERE relname = 'rule_matches'"
    )
    .fetch_one(&pool)
    .await?
    .count
    .ok_or_else(|| ServerFnError::new("No count"))? as usize;
    Ok(count)
}

#[component]
fn TotalRuleMatches() -> impl IntoView {
    view! {
        <Await future=|| async { get_total_rule_matches().await } let:total_rule_matches>
            {match total_rule_matches {
                Ok(count) => view! { {count} }.into_view(),
                Err(err) => view! { {format!("{err:?}")} }.into_view(),
            }}

        </Await>
    }
}

#[server]
async fn get_domain_count() -> Result<usize, ServerFnError> {
    let pool = crate::server::get_db().await?;
    let count = sqlx::query!(
        "SELECT reltuples::bigint AS count
        FROM pg_catalog.pg_class
        WHERE relname = 'domains'"
    )
    .fetch_one(&pool)
    .await?
    .count
    .ok_or_else(|| ServerFnError::new("No count"))? as usize;
    Ok(count)
}

#[component]
fn DomainCount() -> impl IntoView {
    view! {
        <Await future=|| async { get_domain_count().await } let:domain_count>
            {match domain_count {
                Ok(count) => view! { {count} }.into_view(),
                Err(err) => view! { {format!("{err:?}")} }.into_view(),
            }}

        </Await>
    }
}
#[server]
async fn get_subdomains_count() -> Result<usize, ServerFnError> {
    let pool = crate::server::get_db().await?;
    let count = sqlx::query!(
        "SELECT reltuples::bigint AS count
        FROM pg_catalog.pg_class
        WHERE relname = 'subdomains'"
    )
    .fetch_one(&pool)
    .await?
    .count
    .ok_or_else(|| ServerFnError::new("No count"))? as usize;
    Ok(count)
}

#[component]
fn SubdomainCount() -> impl IntoView {
    view! {
        <Await future=|| async { get_subdomains_count().await } let:subdomain_count>
            {match subdomain_count {
                Ok(count) => view! { {count} }.into_view(),
                Err(err) => view! { {format!("{err:?}")} }.into_view(),
            }}

        </Await>
    }
}

#[server]
async fn get_dns_ip_count() -> Result<usize, ServerFnError> {
    let pool = crate::server::get_db().await?;
    let count = sqlx::query!(
        "SELECT reltuples::bigint AS count
            FROM pg_catalog.pg_class
            WHERE relname = 'dns_ips'"
    )
    .fetch_one(&pool)
    .await?
    .count
    .ok_or_else(|| ServerFnError::new("No count"))? as usize;
    Ok(count)
}

#[component]
fn DnsIpCount() -> impl IntoView {
    view! {
        <Await future=|| async { get_dns_ip_count().await } let:dns_ip_count>
            {match dns_ip_count {
                Ok(count) => view! { {count} }.into_view(),
                Err(err) => view! { {format!("{err:?}")} }.into_view(),
            }}

        </Await>
    }
}

#[server]
async fn get_dns_cname_count() -> Result<usize, ServerFnError> {
    let pool = crate::server::get_db().await?;
    let count = sqlx::query!(
        "SELECT reltuples::bigint AS count
            FROM pg_catalog.pg_class
            WHERE relname = 'dns_cnames'"
    )
    .fetch_one(&pool)
    .await?
    .count
    .ok_or_else(|| ServerFnError::new("No count"))? as usize;
    Ok(count)
}

#[component]
fn DnsCnameCount() -> impl IntoView {
    view! {
        <Await future=|| async { get_dns_cname_count().await } let:dns_ip_count>
            {match dns_ip_count {
                Ok(count) => view! { {count} }.into_view(),
                Err(err) => view! { {format!("{err:?}")} }.into_view(),
            }}

        </Await>
    }
}

#[component]
pub fn StatsView() -> impl IntoView {
    view! {
        <div>
            <h1 class="mt-5 mb-5 text-4xl font-bold text-center text-indigo-600">Stats</h1>
            <table class="table max-w-fit">
                <tr>
                    <td>"Total Domains"</td>
                    <td class="text-right">
                        <DomainCount/>
                    </td>
                </tr>
                <tr>
                    <td>"Total DNS IPs"</td>
                    <td class="text-right">
                        <DnsIpCount/>
                    </td>
                </tr>
                <tr>
                    <td>"Total DNS CNAMES"</td>
                    <td class="text-right">
                        <DnsCnameCount/>
                    </td>
                </tr>
                <tr>
                    <td>"Total Subdomains"</td>
                    <td class="text-right">
                        <SubdomainCount/>
                    </td>
                </tr>
                <tr>
                    <td>"Total Rules"</td>
                    <td class="text-right">
                        <TotalRuleCount/>
                    </td>
                </tr>
                <tr>
                    <td>"Total Rule Matches"</td>
                    <td class="text-right">
                        <TotalRuleMatches/>
                    </td>
                </tr>
            </table>
        </div>
    }
}
