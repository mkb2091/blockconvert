#[cfg(feature = "ssr")]
#[tokio::main]
async fn main() {
    use axum::Router;
    use blockconvert::app::App;
    use blockconvert::fileserv::file_and_error_handler;
    use blockconvert::{filterlist, server};
    use leptos::*;
    use leptos_axum::{generate_route_list, LeptosRoutes};
    env_logger::init();

    // Setting get_configuration(None) means we'll be using cargo-leptos's env values
    // For deployment these variables are:
    // <https://github.com/leptos-rs/start-axum#executing-a-server-on-a-remote-machine-without-the-toolchain>
    // Alternately a file can be specified such as Some("Cargo.toml")
    // The file would need to be included with the executable when moved to deployment
    let conf = get_configuration(None).await.unwrap();
    let leptos_options = conf.leptos_options;
    let addr = leptos_options.site_addr;
    let routes = generate_route_list(App);
    //let state = State { leptos_options };
    // build our application with a route
    let app = Router::new()
        .leptos_routes(&leptos_options, routes, App)
        .fallback(file_and_error_handler)
        .with_state(leptos_options);
    let token = tokio_util::sync::CancellationToken::new();
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(filterlist::watch_filter_map());
    tasks.spawn(server::parse_missing_subdomains());
    tasks.spawn(server::check_dns(token.clone()));
    tasks.spawn(server::import_pihole_logs());
    tasks.spawn(blockconvert::rule::find_rule_matches());
    tasks.spawn(server::build_list());
    tasks.spawn(server::update_expired_lists());
    tasks.spawn(server::garbage_collect());
    tasks.spawn(server::run_cmd(token.clone()));
    tasks.spawn(server::certstream(token.clone()));

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    tasks.spawn(async move {
        logging::log!("listening on http://{}", &addr);
        axum::serve(listener, app.into_make_service()).await?;
        Ok(())
    });
    {
        let token = token.clone();
        tasks.spawn(async move {
            let mut interrupt =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).unwrap();
            let mut hangup =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).unwrap();
            let mut terminate =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
            tokio::select! {
                _ = tokio::signal::ctrl_c() =>
                    logging::log!("Ctrl-C received, shutting down"),
                _ = interrupt.recv() =>
                    logging::log!("Interrupt received, shutting down"),
                _ = hangup.recv() =>
                    logging::log!("Hangup received, shutting down"),
                _ = terminate.recv() =>
                    logging::log!("Terminate received, shutting down"),
            }
            token.cancel();
            Ok(())
        });
    }

    while let Some(task) = tasks.join_next().await {
        if let Err(e) = task.unwrap() {
            logging::log!("Error: {:?}", e);
            return;
        }
        logging::log!("Task completed");
        if token.is_cancelled() {
            logging::log!("Shutting down");
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            break;
        }
    }
    logging::log!("Exiting");
}

#[cfg(not(feature = "ssr"))]
pub fn main() {
    // no client-side main function
    // unless we want this to work with e.g., Trunk for a purely client-side app
    // see lib.rs for hydration function instead
}
