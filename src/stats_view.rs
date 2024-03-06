use leptos::*;

#[server]
async fn count_total_rules() -> Result<usize, ServerFnError> {
    let pool = crate::server::get_db().await?;
    let count = sqlx::query!("SELECT COUNT(*) FROM Rules")
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
async fn get_domain_count() -> Result<usize, ServerFnError> {
    let pool = crate::server::get_db().await?;
    let count = sqlx::query!("SELECT COUNT(*) FROM domains")
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
    let count = sqlx::query!("SELECT COUNT(*) FROM subdomains")
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
async fn get_dns_lookup_count() -> Result<usize, ServerFnError> {
    let pool = crate::server::get_db().await?;
    let count = sqlx::query!("SELECT COUNT(*) FROM domains WHERE last_checked_dns IS NOT NULL")
        .fetch_one(&pool)
        .await?
        .count
        .ok_or_else(|| ServerFnError::new("No count"))? as usize;
    Ok(count)
}

#[component]
fn DnsLookupCount() -> impl IntoView {
    view! {
        <Await future=|| async { get_dns_lookup_count().await } let:dns_lookup_count>
            {match dns_lookup_count {
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
            <h1 class="text-4xl font-bold text-indigo-600 mt-5 mb-5 text-center">Stats</h1>
            <table class="table max-w-fit">
                <tr>
                    <td>"Total Domains"</td>
                    <td class="text-right">
                        <DomainCount/>
                    </td>
                </tr>
                <tr>
                    <td>"Total DNS Lookups"</td>
                    <td class="text-right">
                        <DnsLookupCount/>
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
            </table>
        </div>
    }
}
