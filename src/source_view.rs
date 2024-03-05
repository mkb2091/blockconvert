use crate::app::Loading;

use crate::{ListId, RuleId, SourceId};
use leptos::*;
use leptos_router::*;

#[derive(Params, PartialEq)]
struct SourceParam {
    id: i32,
}

type GetId = Box<dyn Fn() -> Result<SourceId, ParamsError>>;

#[server]
async fn get_source(id: SourceId) -> Result<(RuleId, String), ServerFnError> {
    let record = sqlx::query!(
        "SELECT rule_id, source from rule_source WHERE id = $1",
        id.0
    )
    .fetch_one(&crate::server::get_db().await?)
    .await?;
    let source = record.source.as_str().into();
    Ok((RuleId(record.rule_id), source))
}

#[server]
async fn get_lists(id: SourceId) -> Result<Vec<(ListId, String)>, ServerFnError> {
    let lists = sqlx::query!(
        "SELECT list_id, url FROM list_rules
        INNER JOIN filterLists ON list_rules.list_id = filterLists.id
        WHERE source_id = $1
        ",
        id.0
    )
    .fetch_all(&crate::server::get_db().await?)
    .await?;
    Ok(lists
        .into_iter()
        .map(|record| (ListId(record.list_id), record.url.as_str().into()))
        .collect())
}

#[component]
fn Lists(get_id: GetId) -> impl IntoView {
    let lists = create_resource(get_id, |id| async move {
        let lists = get_lists(id?).await?;
        Ok::<_, ServerFnError>(lists)
    });
    view! {
        <Transition fallback=move || {
            view! { <p>"Loading" <Loading/></p> }
        }>
            {move || match lists.get() {
                Some(Ok(lists)) => {
                    view! {
                        <For
                            each=move || { lists.clone() }
                            key=|(id, _)| *id
                            children=|(source_id, source)| {
                                let source_href = format!("/list/{}", source_id.0);
                                view! {
                                    <p>
                                        <A href=source_href class="link link-neutral">
                                            {source}
                                        </A>
                                    </p>
                                }
                            }
                        />
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
fn SourceRawView(
    source: Resource<Result<SourceId, ParamsError>, Result<(RuleId, String), ServerFnError>>,
) -> impl IntoView {
    view! {
        <Transition fallback=move || {
            view! { <p>"Loading" <Loading/></p> }
        }>
            {move || match source.get() {
                Some(Ok((_rule_id, source))) => {
                    view! {
                        <div class="mockup-code">
                            <code>{source}</code>
                        </div>
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
pub fn SourceViewPage() -> impl IntoView {
    let params = use_params::<SourceParam>();
    let get_id = move || {
        params.with(|param| {
            param
                .as_ref()
                .map(|param| SourceId(param.id))
                .map_err(Clone::clone)
        })
    };
    let source_resource = create_resource(get_id, |id| async move {
        let rule = get_source(id?).await?;
        Ok::<_, ServerFnError>(rule)
    });
    view! {
        <SourceRawView source=source_resource/>
        <Lists get_id=Box::new(get_id)/>
    }
}
