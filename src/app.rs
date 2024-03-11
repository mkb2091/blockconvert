use crate::{
    domain::DomainViewPage,
    domain_import_view::DomainImportView,
    error_template::{AppError, ErrorTemplate},
    filterlist::FilterListPage,
    home_page::HomePage,
    ip_view::IpView,
    rule::RuleViewPage,
    stats_view::StatsView,
};
use leptos::*;
use leptos_meta::*;
use leptos_router::*;

#[component]
pub fn App() -> impl IntoView {
    // Provides context that manages stylesheets, titles, meta tags, etc.
    provide_meta_context();

    view! {
        <Stylesheet id="leptos" href="/pkg/blockconvert.css"/>
        <Meta
            http_equiv="Content-Security-Policy"
            content=move || {
                leptos::nonce::use_nonce()
                    .map(|nonce| {
                        format!(
                            "script-src 'strict-dynamic' 'nonce-{nonce}' \
                            'wasm-unsafe-eval';",
                        )
                    })
                    .unwrap_or_default()
            }
        />

        <Title text="BlockConvert"/>
        // content for this welcome page
        <Router fallback=|| {
            let mut outside_errors = Errors::default();
            outside_errors.insert_with_default_key(AppError::NotFound);
            view! { <ErrorTemplate outside_errors/> }.into_view()
        }>

            <header class="p-4 text-white bg-indigo-600">
                <nav class="container flex items-center justify-between mx-auto">
                    <A href="/" class="text-lg font-bold">
                        Home
                    </A>
                    <div class="space-x-4">
                        <A href="/tasks" class="hover:text-indigo-300">
                            Tasks
                        </A>
                        <A href="/stats" class="hover:text-indigo-300">
                            Stats
                        </A>
                        <A href="/import-domains" class="hover:text-indigo-300">
                            Import Domains
                        </A>
                        <A
                            href="/login"
                            class="px-4 py-2 text-indigo-600 bg-white rounded hover:bg-indigo-200"
                        >
                            Login
                        </A>
                    </div>
                </nav>
            </header>
            <main>
                <Routes>
                    <Route path="" view=HomePage ssr=SsrMode::Async/>
                    <Route path="tasks" view=crate::tasks::TaskView ssr=SsrMode::Async/>
                    <Route path="stats" view=StatsView ssr=SsrMode::InOrder/>
                    <Route path="list" view=FilterListPage ssr=SsrMode::InOrder/>
                    <Route path="rule/:id" view=RuleViewPage ssr=SsrMode::InOrder/>
                    <Route path="domain/:domain" view=DomainViewPage ssr=SsrMode::InOrder/>
                    <Route path="ip/:ip" view=IpView ssr=SsrMode::InOrder/>
                    <Route
                        path="import-domains"
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
