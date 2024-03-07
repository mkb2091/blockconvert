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
                <LastUpdated url=url.clone()/>
            </td>
            <td class="text-right">
                <ListSize url=url.clone()/>
            </td>
            <td>
                <FilterListUpdate url=url.clone()/>
                <ParseList url=url.clone()/>
            </td>
        </tr>
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
/// Renders the home page of your application.
#[component]
pub fn HomePage() -> impl IntoView {
    let once = create_resource(
        || (),
        |_| async move { crate::list_manager::get_filter_map().await },
    );

    view! {
        <UpdateAll/>
        <ReparseAll/>
        <Transition fallback=move || {
            view! { <p>"Loading" <Loading/></p> }
        }>
            {move || match once.get() {
                None => view! {}.into_view(),
                Some(Err(err)) => view! { <p>"Error Loading " {format!("{err:?}")}</p> }.into_view(),
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
                                <td>"Size"</td>
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
