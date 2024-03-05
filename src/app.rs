use crate::{
    domain_import_view::DomainImportView,
    domain_view::DomainViewPage,
    error_template::{AppError, ErrorTemplate},
    ip_view::IpView,
    list_manager,
    rule_view::{DisplayRule, RuleData, RuleViewPage},
    source_view::SourceViewPage,
    RuleId, SourceId,
};
use leptos::*;
use leptos_meta::*;
use leptos_router::*;

use std::{str::FromStr, sync::Arc};

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

#[derive(Params, PartialEq, Debug)]
struct ViewListParams {
    url: String,
    page: Option<usize>,
}

impl ViewListParams {
    fn parse(&self) -> Result<crate::FilterListUrl, ViewListError> {
        let url = url::Url::parse(&self.url)?;
        Ok(crate::FilterListUrl::new(url))
    }
}

#[derive(thiserror::Error, Debug)]
enum ViewListError {
    #[error("Invalid URL")]
    ParseURL(#[from] url::ParseError),
    #[error("Invalid URL")]
    ParseParam(#[from] leptos_router::ParamsError),
    #[error("Invalid FilterListType")]
    InvalidFilterListType(#[from] crate::InvalidFilterListTypeError),
}

#[server]
async fn get_list_page(
    url: crate::FilterListUrl,
    page: Option<usize>,
    page_size: usize,
) -> Result<Vec<(RuleId, SourceId, crate::list_parser::RulePair)>, ServerFnError> {
    let pool = crate::server::get_db().await?;
    let url_str = url.as_str();
    let id = sqlx::query!("SELECT id FROM filterLists WHERE url = $1", url_str)
        .fetch_one(&pool)
        .await?
        .id;
    let start = page.unwrap_or(0);
    let records = sqlx::query!(
        r#"SELECT Rules.id AS rule_id, rule_source.id AS source_id, rule_source.source,
        domain as "domain: Option<String>" , domain_rules.allow as "domain_allow: Option<bool>", subdomain as "subdomain: Option<bool>",
        ip_network as "ip_network: Option<ipnetwork::IpNetwork>", ip_rules.allow as "ip_allow: Option<bool>"
        FROM list_rules
        INNER JOIN rule_source ON rule_source.id = list_rules.source_id
        INNER JOIN Rules ON Rules.id = rule_source.rule_id
        LEFT JOIN domain_rules ON domain_rules.id = Rules.domain_rule_id
        LEFT JOIN domains ON domains.id = domain_rules.domain_id
        LEFT JOIN ip_rules ON ip_rules.id = Rules.ip_rule_id
        WHERE list_id = $1
        ORDER BY (domain_rules.id, ip_rules.id) DESC NULLS FIRST 
        LIMIT $2 OFFSET $3
    "#r,
        id,
        page_size as i64,
        start as i64
    )
    .fetch_all(&pool)
    .await?;
    let rules = records
        .iter()
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
            Ok((RuleId(record.rule_id), SourceId(record.source_id), pair))
        })
        .collect::<Result<Vec<(_, _, _)>, ServerFnError>>();

    rules
}

#[component]
pub fn Loading() -> impl IntoView {
    view! { <span class="loading loading-spinner loading-sm"></span> }
}

#[component]
fn LastUpdated(
    last_updated: Resource<usize, Result<Option<chrono::NaiveDateTime>, ServerFnError>>,
) -> impl IntoView {
    view! {
        <Transition fallback=move || {
            view! {
                "Loading "
                <Loading/>
            }
        }>
            {move || match last_updated.get() {
                None => view! {}.into_view(),
                Some(Err(err)) => {
                    view! {
                        "Error Loading "
                        {format!("{:?}", err)}
                    }
                        .into_view()
                }
                Some(Ok(None)) => view! { "Never" }.into_view(),
                Some(Ok(Some(ts))) => view! { {format!("{:?}", ts)} }.into_view(),
            }}

        </Transition>
    }
}

type GetListContents =
    Resource<usize, Result<Vec<(RuleId, SourceId, crate::list_parser::RulePair)>, ServerFnError>>;

#[component]
fn Contents(contents: GetListContents) -> impl IntoView {
    view! {
        <Transition fallback=move || {
            view! { <p>"Loading " <Loading/></p> }
        }>
            <table class="table table-zebra">
                <thead>
                    <tr>
                        <th>Source</th>
                        <th>Rule</th>
                    </tr>
                </thead>
                <tbody>
                    <For
                        each=move || {
                            contents
                                .get()
                                .clone()
                                .iter()
                                .flatten()
                                .flatten()
                                .cloned()
                                .collect::<Vec<_>>()
                        }

                        key=|(rule_id, source_id, _)| (*rule_id, *source_id)
                        children=|(rule_id, source_id, pair)| {
                            let source = pair.get_source().to_string();
                            let rule = pair.get_rule().clone();
                            let rule_href = format!("/rule/{}", rule_id.0);
                            let source_href = format!("/rule_source/{}", source_id.0);
                            view! {
                                <tr>
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

                </tbody>
            </table>

        </Transition>
    }
}

#[component]
fn ParseList(url: crate::FilterListUrl, set_updated: Arc<dyn Fn()>) -> impl IntoView {
    let parse_list = create_action(move |url: &crate::FilterListUrl| {
        let url = url.clone();
        let set_updated = set_updated.clone();
        async move {
            log::info!("Parsing {}", url.as_str());
            if let Err(err) = crate::list_parser::parse_list(url).await {
                log::error!("Error parsing list: {:?}", err);
            }
            set_updated();
        }
    });
    view! {
        <button
            on:click={
                let url = url.clone();
                move |_| {
                    log::info!("Parsing {}", url.as_str());
                    parse_list.dispatch(url.clone());
                }
            }

            class="btn btn-primary"
        >
            "Re-parse"
        </button>
    }
}

#[server]
async fn get_list_size(url: crate::FilterListUrl) -> Result<Option<usize>, ServerFnError> {
    let pool = crate::server::get_db().await?;
    let mut tx = pool.begin().await?;
    let url_str = url.as_str();
    let list_id = sqlx::query!("SELECT id FROM filterLists WHERE url = $1", url_str)
        .fetch_one(&mut *tx)
        .await?
        .id;
    let count = sqlx::query!(
        "SELECT COUNT(*) FROM list_rules WHERE list_id = $1",
        list_id
    )
    .fetch_one(&mut *tx)
    .await?
    .count
    .map(|x| x as usize);
    Ok(count)
}

#[component]
fn ListSize(size: Resource<usize, Result<Option<usize>, ServerFnError>>) -> impl IntoView {
    view! {
        <Transition fallback=move || {
            view! {
                "Loading "
                <Loading/>
            }
        }>
            {move || match size.get() {
                None => view! {}.into_view(),
                Some(Err(err)) => {
                    view! {
                        "Error Loading "
                        {format!("{:?}", err)}
                    }
                        .into_view()
                }
                Some(Ok(None)) => view! { "Never" }.into_view(),
                Some(Ok(Some(size))) => view! { {size} }.into_view(),
            }}

        </Transition>
    }
}

#[component]
fn FilterListInner(url: crate::FilterListUrl, page: Option<usize>) -> impl IntoView {
    const PAGE_SIZE: usize = 50;
    let (updated, set_updated) = create_signal(0_usize);
    let set_updated = Arc::new(move || set_updated.update(|x| *x += 1));
    let last_updated = create_resource(updated, {
        let url = url.clone();
        move |_| {
            let url = url.clone();
            async move { crate::list_manager::get_last_updated(url).await }
        }
    });
    let list_size = create_resource(updated, {
        let url = url.clone();
        move |_| {
            let url = url.clone();
            async move { get_list_size(url).await }
        }
    });
    let contents = create_resource(updated, {
        let url = url.clone();
        move |_| {
            let url = url.clone();
            async move { get_list_page(url, page, PAGE_SIZE).await }
        }
    });
    view! {
        <h1>"Filter List"</h1>
        <p>"URL: " {url.to_string()}</p>
        <p>"Last Updated: " <LastUpdated last_updated=last_updated/></p>
        <p>"Rule count: " <ListSize size=list_size/></p>
        <FilterListUpdate url=url.clone() set_updated=set_updated.clone()/>
        <p>
            <ParseList url=url.clone() set_updated=set_updated/>
        </p>
        {if let Some(page) = page {
            view! { <p>"Page: " {page}</p> }
        } else {
            view! { <p>"Page: 0"</p> }
        }}

        {match page {
            None | Some(0) => view! {}.into_view(),
            Some(page) => {
                let params = params_map! {
                    "url" => url.as_str(), "page" => (page.saturating_sub(PAGE_SIZE)).to_string()
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
                "url" => url.as_str(), "page" => (page.unwrap_or(0) + PAGE_SIZE).to_string()
            };
            let href = format!("/list{}", params.to_query_string());
            view! {
                <A href=href class="btn btn-neutral">
                    "Next"
                </A>
            }
        }

        <p>"Contents: " <Contents contents=contents/></p>
    }
}

#[component]
fn FilterListPage() -> impl IntoView {
    let params = use_query::<ViewListParams>();
    let url = move || {
        params.with(|param| {
            param
                .as_ref()
                .ok()
                .map(|param| param.parse().map(|url| (url, param.page)))
        })
    };
    view! {
        <div>

            {move || match url() {
                None => view! { <p>"No URL"</p> }.into_view(),
                Some(Err(err)) => view! { <p>"Error: " {format!("{:?}", err)}</p> }.into_view(),
                Some(Ok((url, page))) => view! { <FilterListInner url=url page=page/> }.into_view(),
            }}

        </div>
    }
}

#[component]
fn FilterListUpdate(url: crate::FilterListUrl, set_updated: Arc<dyn Fn()>) -> impl IntoView {
    #[derive(Clone, PartialEq)]
    enum UpdateStatus {
        Ready,
        Updating,
        Updated,
        FailedtoUpdate(ServerFnError),
    }
    let (updating_status, set_updating_status) = create_signal(UpdateStatus::Ready);
    let update_list = leptos::create_action(move |url: &crate::FilterListUrl| {
        let url = url.clone();
        let set_updated = set_updated.clone();
        async move {
            log::info!("Updating {}", url.as_str());
            set_updating_status.set(UpdateStatus::Updating);
            if let Err(err) = list_manager::update_list(url).await {
                log::error!("Error updating list: {:?}", err);
                set_updating_status.set(UpdateStatus::FailedtoUpdate(err));
            } else {
                set_updating_status.set(UpdateStatus::Updated);
            }
            set_updated();
        }
    });

    view! {
        <button
            on:click={
                let url = url.clone();
                move |_| {
                    update_list.dispatch(url.clone());
                }
            }

            class="btn btn-primary"
        >
            "Update"
        </button>

        {move || match updating_status.get() {
            UpdateStatus::Ready => view! { "Ready" }.into_view(),
            UpdateStatus::Updating => {
                view! {
                    "Updating"
                    <Loading/>
                }
                    .into_view()
            }
            UpdateStatus::Updated => view! { "Updated" }.into_view(),
            UpdateStatus::FailedtoUpdate(err) => {
                view! { {format!("Failed to Update: {:?}", err)} }.into_view()
            }
        }}
    }
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
            <td>{record.license.to_string()}</td>
            <td>{format!("{:?}", record.expires)}</td>
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
        <p>"Total Rules: " <TotalRuleCount/></p>
        <p>"Total Domains: " <DomainCount/></p>
        <p>"Total Subdomains: " <SubdomainCount/></p>
        <p>"Total DNS Lookups: " <DnsLookupCount/></p>
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
