#[cfg(feature = "ssr")]
use self::rule_view::RuleData;
use crate::{
    app::Loading,
    list_manager::{DeleteList, UpdateList},
    rule_view::DisplayRule,
    *,
};
use leptos::*;
use leptos_router::*;

const PAGE_SIZE: usize = 50;

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
    let url_str = url.as_str();
    let record = sqlx::query!(
        "SELECT id, rule_count FROM filterLists WHERE url = $1",
        url_str
    )
    .fetch_one(&pool)
    .await?;
    let list_id = record.id;
    let count = record.rule_count;
    if count == 0 {
        let count = sqlx::query!(
            "SELECT COUNT(*) FROM list_rules WHERE list_id = $1",
            list_id
        )
        .fetch_one(&pool)
        .await?
        .count;
        if let Some(count) = count {
            sqlx::query!(
                "UPDATE filterLists SET rule_count = $1 WHERE id = $2",
                count as i32,
                list_id
            )
            .execute(&pool)
            .await?;
            Ok(Some(count as usize))
        } else {
            Ok(None)
        }
    } else {
        Ok(Some(count as usize))
    }
}

#[component]
pub fn ListSize(url: FilterListUrl, list_size: Option<usize>) -> impl IntoView {
    if let Some(size) = list_size {
        if size > 0 {
            return size.into_view();
        }
    }
    view! {
        <Await
            future=move || {
                let url = url.clone();
                async { get_list_size(url).await }
            }

            let:size
        >
            {match size {
                Err(err) => format!("{err:?}").into_view(),
                Ok(None) => "Never".into_view(),
                Ok(Some(size)) => size.into_view(),
            }}

        </Await>
    }
    .into_view()
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
    let start = page.unwrap_or(0) * page_size;
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
        ORDER BY list_rules.source_id
        LIMIT $2 OFFSET $3
    "#r,
        id,
        page_size as i64 ,
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
fn LastUpdatedInner(last_updated: Option<chrono::DateTime<chrono::Utc>>) -> impl IntoView {
    view! {
        {match last_updated {
            Some(last_updated) => {
                view! { <div>{format!("{last_updated}")}</div> }
            }
            None => {
                view! { <div>"Never"</div> }
            }
        }}
    }
}

#[component]
pub fn LastUpdated(url: FilterListUrl, record: Option<FilterListRecord>) -> impl IntoView {
    view! {
        {match record.clone() {
            Some(record) => {
                let last_updated = record.last_updated;
                view! { <LastUpdatedInner last_updated=last_updated/> }
            }
            None => {
                view! {
                    <Await
                        future={
                            let url = url.clone();
                            move || {
                                let url = url.clone();
                                async move {
                                    crate::list_manager::get_last_updated(url.clone()).await
                                }
                            }
                        }

                        let:last_version_data
                    >
                        {match last_version_data {
                            Ok(last_updated) => {
                                view! { <LastUpdatedInner last_updated=last_updated.clone()/> }
                                    .into_view()
                            }
                            Err(err) => view! { {format!("{err:?}")} }.into_view(),
                        }}

                    </Await>
                }
            }
        }}

        <FilterListUpdate url=url.clone()/>
    }
}

#[component]
pub fn ParseList(url: crate::FilterListUrl) -> impl IntoView {
    let parse_list_action = create_server_action::<crate::list_parser::ParseList>();
    view! {
        <ActionForm action=parse_list_action>
            <button class="btn btn-primary" type="submit">
                <input type="hidden" placeholder="url" id="url" name="url" value=url.to_string()/>
                "Parse"
            </button>
        </ActionForm>
    }
}

#[component]
pub fn FilterListUpdate(url: crate::FilterListUrl) -> impl IntoView {
    let update_list_action = create_server_action::<UpdateList>();
    view! {
        <ActionForm action=update_list_action>
            <button class="btn btn-primary" type="submit">
                <input type="hidden" placeholder="url" id="url" name="url" value=url.to_string()/>
                "Update"
            </button>
        </ActionForm>
    }
}

#[component]
fn Contents(url: crate::FilterListUrl, page: Option<usize>) -> impl IntoView {
    view! {
        <table class="table table-zebra">
            <thead>
                <tr>
                    <th>Source</th>
                    <th>Rule</th>
                </tr>
            </thead>
            <Await
                future=move || {
                    let url = url.clone();
                    async move { get_list_page(url, page, PAGE_SIZE).await }
                }

                let:contents
            >

                {
                    let contents = contents.clone();
                    move || match contents.clone() {
                        Ok(contents) => {
                            let contents = contents.clone();
                            view! {
                                <tbody>
                                    <For
                                        each=move || {
                                            contents.clone().iter().cloned().collect::<Vec<_>>()
                                        }

                                        key=|(rule_id, source_id, _)| (*rule_id, *source_id)
                                        children=|(rule_id, _source_id, pair)| {
                                            let source = pair.get_source().to_string();
                                            let rule = pair.get_rule().clone();
                                            let rule_href = format!("/rule/{}", rule_id.0);
                                            view! {
                                                <tr>
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

                                </tbody>
                            }
                                .into_view()
                        }
                        Err(err) => format!("{err:?}").into_view(),
                    }
                }

            </Await>

        </table>
    }
}

#[component]
fn FilterListInner(url: crate::FilterListUrl, page: Option<usize>) -> impl IntoView {
    view! {
        <h1>"Filter List"</h1>
        <p>"URL: " {url.to_string()}</p>
        <p>"Last Updated: " <LastUpdated url=url.clone() record=None/></p>
        <p>"Rule count: " <ListSize url=url.clone() list_size=None/></p>
        <FilterListUpdate url=url.clone()/>
        <p>
            <ParseList url=url.clone()/>
        </p>

        <DeleteListButton url=url.clone()/>
        {if let Some(page) = page {
            view! { <p>"Page: " {page}</p> }
        } else {
            view! { <p>"Page: 0"</p> }
        }}

        {match page {
            None | Some(0) => view! {}.into_view(),
            Some(page) => {
                let params = params_map! {
                    "url" => url.as_str(), "page" => (page.saturating_sub(1)).to_string()
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
                "url" => url.as_str(), "page" => (page.unwrap_or(0) + 1).to_string()
            };
            let href = format!("/list{}", params.to_query_string());
            view! {
                <A href=href class="btn btn-neutral">
                    "Next"
                </A>
            }
        }

        <p>"Contents: " <Contents url=url.clone() page=page/></p>
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
        Ok(self.url.parse()?)
    }
}

#[component]
fn DeleteListButton(url: FilterListUrl) -> impl IntoView {
    let delete_list_action = create_server_action::<DeleteList>();
    view! {
        <ActionForm action=delete_list_action>
            <button class="btn btn-danger" type="submit">
                <input type="hidden" placeholder="url" id="url" name="url" value=url.to_string()/>
                "Delete"
            </button>
        </ActionForm>
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
                Some(Err(err)) => view! { <p>"Error: " {format!("{err}")}</p> }.into_view(),
                Some(Ok((url, page))) => view! { <FilterListInner url=url page=page/> }.into_view(),
            }}

        </div>
    }
}
