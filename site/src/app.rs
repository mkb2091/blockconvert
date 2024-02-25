use crate::{
    error_template::{AppError, ErrorTemplate},
    list_manager,
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
        <Stylesheet id="leptos" href="/pkg/site.css"/>

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
                <Routes>
                    <Route path="" view=HomePage ssr=SsrMode::InOrder/>
                    <Route path="list" view=FilterListPage/>
                </Routes>
            </main>
        </Router>
    }
}

#[derive(Params, PartialEq, Debug)]
struct ViewListParams {
    url: String,
    list_format: String,
}

impl ViewListParams {
    fn parse(&self) -> Result<crate::FilterListUrl, ViewListError> {
        log::info!("Parsing: {:?}", self);
        let url = url::Url::parse(&self.url)?;
        let list_format = crate::FilterListType::from_str(&self.list_format)?;
        Ok(crate::FilterListUrl::new(url, list_format))
    }
}

#[derive(thiserror::Error, Debug)]
enum ViewListError {
    #[error("Invalid URL")]
    ParseError(#[from] url::ParseError),
    #[error("Invalid URL")]
    ParamError(#[from] leptos_router::ParamsError),
    #[error("Invalid FilterListType")]
    InvalidFilterListTypeError(#[from] crate::InvalidFilterListTypeError),
}

#[server]
async fn get_list(
    url: crate::FilterListUrl,
) -> Result<Vec<crate::list_parser::RulePair>, ServerFnError> {
    let pool = crate::server::get_db().await?;
    let url_str = url.as_str();
    let id = sqlx::query!("SELECT id FROM filterLists WHERE url = ?", url_str)
        .fetch_one(&pool)
        .await?
        .id;
    let records = sqlx::query!("SELECT rule, source FROM list_rules JOIN Rules ON list_rules.rule_id = Rules.id WHERE list_id = ?", id)
        .fetch_all(&pool)
        .await?;
    let rules = records
        .iter()
        .map(|record| {
            let rule: crate::list_parser::Rule = serde_json::from_str(&record.rule)?;
            let source = record.source.clone().unwrap();
            Ok(crate::list_parser::RulePair::new(source, rule))
        })
        .collect::<Result<Vec<crate::list_parser::RulePair>, serde_json::Error>>();

    Ok(rules?)
}

#[component]
fn Loading() -> impl IntoView {
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

#[component]
fn Contents(
    contents: Resource<usize, Result<Vec<crate::list_parser::RulePair>, ServerFnError>>,
) -> impl IntoView {
    view! {
        <Transition fallback=move || {
            view! { <p>"Loading " <Loading/></p> }
        }>
            {move || match contents.get() {
                None => view! {}.into_view(),
                Some(Err(err)) => {
                    view! {
                        "Error Loading "
                        {format!("{:?}", err)}
                    }
                        .into_view()
                }
                Some(Ok(data)) => {
                    view! {
                        <table class="table table-zebra">
                            <tbody>
                                <For
                                    each=move || { data.clone() }
                                    key=|pair| pair.clone()
                                    children=|pair| {
                                        view! {
                                            <tr>
                                                <td>{pair.get_source()}</td>
                                                <td>{format!("{:?}", pair.get_rule())}</td>
                                            </tr>
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
#[server]
async fn parse_list(url: crate::FilterListUrl) -> Result<(), ServerFnError> {
    log::info!("Parsing {}", url.as_str());
    let pool = crate::server::get_db().await?;
    let url_str = url.as_str();
    let record = sqlx::query!(
        "SELECT id, contents FROM filterLists WHERE url = ?",
        url_str
    )
    .fetch_one(&pool)
    .await?;
    let list_id = record.id;
    let contents = record.contents;
    let rules = crate::list_parser::parse_list(&contents, url.list_format);
    for rule in rules.iter() {
        let source = rule.get_source();
        let rule = rule.get_rule();
        let encoded_rule = serde_json::to_string(rule)?;
        sqlx::query!(
            "INSERT OR IGNORE INTO Rules (rule) VALUES (?)",
            encoded_rule
        )
        .execute(&pool)
        .await?;
        let rule_id = sqlx::query!("SELECT id FROM Rules WHERE rule = ?", encoded_rule)
            .fetch_one(&pool)
            .await?
            .id;
        sqlx::query!(
            "INSERT INTO list_rules (list_id, rule_id, source) VALUES (?, ?, ?)",
            list_id,
            rule_id,
            source
        )
        .execute(&pool)
        .await?;
    }
    Ok(())
}

#[component]
fn ParseList(url: crate::FilterListUrl, set_updated: Arc<dyn Fn()>) -> impl IntoView {
    let parse_list = create_action(move |url: &crate::FilterListUrl| {
        let url = url.clone();
        let set_updated = set_updated.clone();
        async move {
            log::info!("Parsing {}", url.as_str());
            if let Err(err) = parse_list(url).await {
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
fn FilterListInner(url: crate::FilterListUrl) -> impl IntoView {
    let (updated, set_updated) = create_signal(0_usize);
    let set_updated = Arc::new(move || set_updated.update(|x| *x += 1));
    let last_updated = create_resource(updated, {
        let url = url.clone();
        move |_| {
            let url = url.clone();
            async move { crate::list_manager::get_last_updated(url).await }
        }
    });
    let contents = create_resource(updated, {
        let url = url.clone();
        move |_| {
            let url = url.clone();
            async move { get_list(url).await }
        }
    });
    view! {
        <h1>"Filter List"</h1>
        <p>"URL: " {url.to_string()}</p>
        <p>"Last Updated: " <LastUpdated last_updated=last_updated/></p>
        <FilterListUpdate url=url.clone() set_updated=set_updated.clone()/>
        <p>
            <ParseList url=url.clone() set_updated=set_updated/>
        </p>
        <p>"Contents: " <Contents contents=contents/></p>
    }
}

#[component]
fn FilterListPage() -> impl IntoView {
    let params = use_query::<ViewListParams>();
    let url = move || params.with_untracked(|param| param.as_ref().ok().map(|param| param.parse()));
    view! {
        <div>

            {match url() {
                None => view! { <p>"No URL"</p> }.into_view(),
                Some(Err(err)) => view! { <p>"Error: " {format!("{:?}", err)}</p> }.into_view(),
                Some(Ok(url)) => view! { <FilterListInner url=url/> }.into_view(),
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
                        "/list?url={}&list_format={}",
                        url::form_urlencoded::byte_serialize(url.as_str().as_bytes())
                            .collect::<String>(),
                        url::form_urlencoded::byte_serialize(url.list_format.as_str().as_bytes())
                            .collect::<String>(),
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
            <td>{format!("{:?}", url.list_format)}</td>
            <td>
                <LastUpdated last_updated=last_updated/>
            </td>
            <td>
                <FilterListUpdate url=url.clone() set_updated=set_updated/>
            </td>
        </tr>
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
