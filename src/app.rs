use crate::{
    domain_import_view::DomainImportView,
    domain_view::DomainViewPage,
    error_template::{AppError, ErrorTemplate},
    ip_view::IpView,
    list_view::{FilterListPage, FilterListUpdate, LastUpdated, ParseList},
    rule_view::RuleViewPage,
    source_view::SourceViewPage,
};
use leptos::*;
use leptos_meta::*;
use leptos_router::*;

use std::sync::Arc;

#[component]
pub fn App() -> impl IntoView {
    // Provides context that manages stylesheets, titles, meta tags, etc.
    provide_meta_context();

    view! {
        <Stylesheet id="leptos" href="/pkg/blockconvert.css"/>

        // sets the document title
        <Title text="Welcome to Leptos"/>

        // content for this welcome page
        <Router fallback=|| {
            let mut outside_errors = Errors::default();
            outside_errors.insert_with_default_key(AppError::NotFound);
            view! { <ErrorTemplate outside_errors/> }.into_view()
        }>
            <main>
                <A href="" class="link link-neutral">
                    <h1 class="text-3xl">"Home"</h1>
                </A>
                <A href="/import_domains" class="link link-neutral">
                    <h1 class="text-2xl">"Import Domains"</h1>
                </A>
                <Routes>
                    <Route path="" view=HomePage ssr=SsrMode::InOrder/>
                    <Route path="list" view=FilterListPage ssr=SsrMode::InOrder/>
                    <Route path="rule/:id" view=RuleViewPage ssr=SsrMode::InOrder/>
                    <Route path="rule_source/:id" view=SourceViewPage ssr=SsrMode::InOrder/>
                    <Route path="domain/:domain" view=DomainViewPage ssr=SsrMode::InOrder/>
                    <Route path="ip/:ip" view=IpView ssr=SsrMode::InOrder/>
                    <Route
                        path="import_domains"
                        view=DomainImportView
                        methods=&[Method::Get, Method::Post]
                        ssr=SsrMode::InOrder
                    />
                </Routes>
            </main>
        </Router>
    }
}

#[component]
pub fn Loading() -> impl IntoView {
    view! { <span class="loading loading-spinner loading-sm"></span> }
}

#[component]
fn FilterListSummary(url: crate::FilterListUrl, record: crate::FilterListRecord) -> impl IntoView {
    let url_clone = url.clone();

    let (updated, set_updated) = create_signal(0_usize);
    let set_updated = Arc::new(move || set_updated.update(|x| *x += 1));

    let last_updated = create_resource(updated, move |_| {
        let url = url_clone.clone();
        async move { crate::list_manager::get_last_updated(url).await }
    });
    view! {
        <tr>
            <td class="max-w-20 break-normal break-words">

                {
                    let name = if record.name.is_empty() {
                        url.to_string()
                    } else {
                        record.name.to_string()
                    };
                    let href = format!(
                        "/list{}",
                        params_map! {
                            "url" => url.as_str(),
                        }
                            .to_query_string(),
                    );
                    view! {
                        <A href=href class="link link-neutral">
                            {name}
                        </A>
                    }
                }

            </td>
            <td class="max-w-20 break-normal break-words">{record.author.to_string()}</td>
            <td class="max-w-xl break-normal break-words">{record.license.to_string()}</td>
            <td>{humantime::format_duration(record.expires).to_string()}</td>
            <td>{format!("{:?}", record.list_format)}</td>
            <td>
                <LastUpdated last_updated=last_updated/>
            </td>
            <td>
                <FilterListUpdate url=url.clone() set_updated=set_updated.clone()/>
                <ParseList url=url.clone() set_updated=set_updated/>
            </td>
        </tr>
    }
}

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
    let total_rules = create_resource(|| (), |_| async move { count_total_rules().await });
    view! {
        <Transition fallback=move || {
            view! {
                "Loading "
                <Loading/>
            }
        }>
            {move || match total_rules.get() {
                None => view! {}.into_view(),
                Some(Err(err)) => {
                    view! {
                        "Error Loading "
                        {format!("{:?}", err)}
                    }
                        .into_view()
                }
                Some(Ok(count)) => view! { {count} }.into_view(),
            }}

        </Transition>
    }
}

#[component]
fn ReparseAll() -> impl IntoView {
    let reparse_all = leptos::create_action(|_| async move {
        log::info!("Re-parsing all lists");
        let map = crate::list_manager::get_filter_map().await?;
        for (url, _) in map.0 {
            let out = crate::list_parser::parse_list(url.clone()).await;
            log::info!("Re-parsing {:?}: {:?}", url, out);
        }
        Ok::<_, ServerFnError>(())
    });
    view! {
        <button
            on:click=move |_| {
                reparse_all.dispatch(());
            }

            class="btn btn-primary"
        >
            "Re-parse All"
        </button>
    }
}
#[component]
fn UpdateAll() -> impl IntoView {
    let update_all = leptos::create_action(|_| async move {
        log::info!("Updating all lists");
        let map = crate::list_manager::get_filter_map().await?;
        for (url, _) in map.0 {
            let out = crate::list_manager::update_list(url.clone()).await;
            log::info!("Updating {:?}: {:?}", url, out);
        }
        Ok::<_, ServerFnError>(())
    });
    view! {
        <button
            on:click=move |_| {
                update_all.dispatch(());
            }

            class="btn btn-primary"
        >
            "Update All"
        </button>
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

#[server]
async fn get_processed_subdomains_count() -> Result<usize, ServerFnError> {
    let pool = crate::server::get_db().await?;
    let count = sqlx::query!("SELECT COUNT(*) FROM subdomains")
        .fetch_one(&pool)
        .await?
        .count
        .ok_or_else(|| ServerFnError::new("No count"))? as usize;
    Ok(count)
}

#[component]
fn DomainCount() -> impl IntoView {
    let domain_count = create_resource(|| (), |_| async move { get_domain_count().await });
    view! {
        <Transition fallback=move || {
            view! {
                "Loading "
                <Loading/>
            }
        }>
            {move || match domain_count.get() {
                None => view! {}.into_view(),
                Some(Err(err)) => {
                    view! {
                        "Error Loading "
                        {format!("{:?}", err)}
                    }
                        .into_view()
                }
                Some(Ok(count)) => view! { {count} }.into_view(),
            }}

        </Transition>
    }
}

#[component]
fn SubdomainCount() -> impl IntoView {
    let subdomain_count = create_resource(
        || (),
        |_| async move { get_processed_subdomains_count().await },
    );
    view! {
        <Transition fallback=move || {
            view! {
                "Loading "
                <Loading/>
            }
        }>
            {move || match subdomain_count.get() {
                None => view! {}.into_view(),
                Some(Err(err)) => {
                    view! {
                        "Error Loading "
                        {format!("{:?}", err)}
                    }
                        .into_view()
                }
                Some(Ok(count)) => view! { {count} }.into_view(),
            }}

        </Transition>
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
    let dns_lookup_count = create_resource(|| (), |_| async move { get_dns_lookup_count().await });
    view! {
        <Transition fallback=move || {
            view! {
                "Loading "
                <Loading/>
            }
        }>
            {move || match dns_lookup_count.get() {
                None => view! {}.into_view(),
                Some(Err(err)) => {
                    view! {
                        "Error Loading "
                        {format!("{:?}", err)}
                    }
                        .into_view()
                }
                Some(Ok(count)) => view! { {count} }.into_view(),
            }}

        </Transition>
    }
}

/// Renders the home page of your application.
#[component]
fn HomePage() -> impl IntoView {
    let once = create_resource(
        || (),
        |_| async move { crate::list_manager::get_filter_map().await },
    );

    view! {
        <h1>"Welcome to Leptos!"</h1>
        <table class="table max-w-fit">
            <tr>
                <td>"Total Rules"</td>
                <td>
                    <TotalRuleCount/>
                </td>
            </tr>
            <tr>
                <td>"Total Domains"</td>
                <td>
                    <DomainCount/>
                </td>
            </tr>
            <tr>
                <td>"Total Subdomains"</td>
                <td>
                    <SubdomainCount/>
                </td>
            </tr>
            <tr>
                <td>"Total DNS Lookups"</td>
                <td>
                    <DnsLookupCount/>
                </td>
            </tr>
        </table>
        <UpdateAll/>
        <ReparseAll/>
        <Transition fallback=move || {
            view! { <p>"Loading" <Loading/></p> }
        }>
            {move || match once.get() {
                None => view! {}.into_view(),
                Some(Err(err)) => {
                    view! { <p>"Error Loading " {format!("{:?}", err)}</p> }.into_view()
                }
                Some(Ok(data)) => {
                    log::info!("Displaying list");
                    view! {
                        <table class="table table-zebra">
                            <thead>
                                <td>"Name"</td>
                                <td>"Author"</td>
                                <td>"License"</td>
                                <td>"Update frequency"</td>
                                <td>"Format"</td>
                                <td>"Last Updated"</td>
                            </thead>
                            <tbody>
                                <For
                                    each=move || { data.0.clone() }
                                    key=|(url, _)| url.as_str().to_string()
                                    children=|(url, record)| {
                                        view! {
                                            <FilterListSummary url=url.clone() record=record.clone()/>
                                        }
                                    }
                                />

                            </tbody>
                        </table>
                    }
                        .into_view()
                }
            }}

        </Transition>
    }
}
