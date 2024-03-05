#[cfg(feature = "ssr")]
use self::rule_view::RuleData;
use crate::{app::Loading, rule_view::DisplayRule, *};
use leptos::*;
use leptos_router::*;

#[component]
pub fn FilterListLink(url: crate::FilterListUrl) -> impl IntoView {
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
pub fn LastUpdated(
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
                Some(Ok(Some(ts))) => view! { {format!("{}", ts)} }.into_view(),
            }}

        </Transition>
    }
}

#[component]
pub fn ParseList(url: crate::FilterListUrl, set_updated: Arc<dyn Fn()>) -> impl IntoView {
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

#[component]
pub fn FilterListUpdate(url: crate::FilterListUrl, set_updated: Arc<dyn Fn()>) -> impl IntoView {
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

        <DeleteList url=url.clone()/>
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

#[derive(Params, PartialEq, Debug)]
struct ViewListParams {
    url: String,
    page: Option<usize>,
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

impl ViewListParams {
    fn parse(&self) -> Result<crate::FilterListUrl, ViewListError> {
        Ok(url::Url::parse(&self.url)?.into())
    }
}

#[component]
fn DeleteList(url: FilterListUrl) -> impl IntoView {
    let delete_list = create_action(move |url: &FilterListUrl| {
        let url = url.clone();
        async move {
            log::info!("Deleting {}", url.as_str());
            if let Err(err) = list_manager::delete_list(url).await {
                log::error!("Error deleting list: {:?}", err);
            }
        }
    });
    view! {
        <button
            class="btn btn-danger"
            on:click={
                let url = url.clone();
                move |_| {
                    delete_list.dispatch(url.clone());
                }
            }
        >

            "Delete"
        </button>
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
                Some(Err(err)) => view! { <p>"Error: " {format!("{}", err)}</p> }.into_view(),
                Some(Ok((url, page))) => view! { <FilterListInner url=url page=page/> }.into_view(),
            }}

        </div>
    }
}
