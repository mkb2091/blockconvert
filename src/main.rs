#[cfg(feature = "ssr")]
#[tokio::main]
async fn main() {
    use axum::Router;
    use blockconvert::app::App;
    use blockconvert::fileserv::file_and_error_handler;
    use blockconvert::{list_manager, server};
    use futures::StreamExt;
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

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    let mut tasks = futures::stream::FuturesUnordered::new();
    tasks.push(tokio::spawn(list_manager::watch_filter_map()));
    tasks.push(tokio::spawn(server::parse_missing_subdomains()));
    tasks.push(tokio::spawn(server::check_dns()));
    tasks.push(tokio::spawn(server::import_pihole_logs()));
    tasks.push(tokio::spawn(server::find_rule_matches()));
    tasks.push(tokio::spawn(server::build_list()));
    tasks.push(tokio::spawn(server::update_expired_lists()));
    tasks.push(tokio::spawn(server::garbage_collect()));
    tasks.push(tokio::spawn(async move {
        logging::log!("listening on http://{}", &addr);
        axum::serve(listener, app.into_make_service()).await?;
        Ok(())
    }));

    while let Some(task) = tasks.next().await {
        if let Err(e) = task.unwrap() {
            logging::log!("Error: {:?}", e);
            return;
        } else {
            logging::log!("Task completed");
        }
    }
}

#[cfg(not(feature = "ssr"))]
pub fn main() {
    // no client-side main function
    // unless we want this to work with e.g., Trunk for a purely client-side app
    // see lib.rs for hydration function instead
}
