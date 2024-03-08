use crate::{
    app::Loading,
    list_view::{FilterListUpdate, LastUpdated, ListSize, ParseList},
};
use leptos::*;
use leptos_router::*;

#[component]
fn FilterListSummary(url: crate::FilterListUrl, record: crate::FilterListRecord) -> impl IntoView {
    view! {
        <tr>
            <td class="break-normal break-words max-w-20">

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
            <td class="break-normal break-words max-w-20">{record.author.to_string()}</td>
            <td class="max-w-xl break-normal break-words">{record.license.to_string()}</td>
            <td>{humantime::format_duration(record.expires).to_string()}</td>
            <td>{format!("{:?}", record.list_format)}</td>
            <td>
                <LastUpdated url=url.clone() record=Some(record.clone())/>
            </td>
            <td class="text-right">
                <ListSize url=url.clone() list_size=Some(record.list_size)/>
            </td>
        </tr>
    }
}

/// Renders the home page of your application.
#[component]
pub fn HomePage() -> impl IntoView {
    view! {
        <Await
            future=|| async move { crate::list_manager::get_filter_map().await }
            let:filterlist_map
        >
            {match filterlist_map.clone() {
                Ok(data) => {
                    view! {
                        <table class="table table-zebra">
                            <thead>
                                <td>"Name"</td>
                                <td>"Author"</td>
                                <td>"License"</td>
                                <td>"Update frequency"</td>
                                <td>"Format"</td>
                                <td>"Last Updated"</td>
                                <td>"Size"</td>
                            </thead>
                            <tbody>
                                <For
                                    each=move || {
                                        let mut data = data.0.clone();
                                        data.sort_unstable_by(|a, b| {
                                            b.1.last_updated.cmp(&a.1.last_updated)
                                        });
                                        data
                                    }

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
                Err(err) => view! { <p>"Error Loading " {format!("{err:?}")}</p> }.into_view(),
            }}

        </Await>
    }
}
