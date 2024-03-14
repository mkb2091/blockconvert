#[cfg(feature = "ssr")]
use clap::Parser;

#[cfg(feature = "ssr")]
#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct Config {
    listen_port: u16,
    peers: Vec<blockconvert::server::Peer>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_port: 3000,
            peers: vec![Default::default(); 2],
        }
    }
}

#[cfg(feature = "ssr")]
/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    config_path: std::path::PathBuf,
    #[arg(short, long)]
    create_config: bool,
    #[arg(short, long)]
    run_tasks: bool,
}

#[cfg(feature = "ssr")]
#[tokio::main]
async fn main() {
    use axum::Router;
    use blockconvert::app::App;
    use blockconvert::fileserv::file_and_error_handler;
    use blockconvert::{filterlist, server};
    use leptos::*;
    use leptos_axum::{generate_route_list, LeptosRoutes};
    use tower_http::compression::CompressionLayer;
    use tower_http::compression::CompressionLevel;
    env_logger::init();

    let args = Args::parse();
    let config_path = args.config_path.clone();
    let node_conf = if let Ok(conf) = tokio::fs::read_to_string(args.config_path).await {
        let Ok(conf): Result<Config, _> = toml::from_str(&conf) else {
            logging::warn!("Error parsing config file");
            return;
        };
        conf
    } else if args.create_config {
        let conf = Config::default();
        let conf_str = toml::to_string(&conf).unwrap();
        tokio::fs::write(config_path, conf_str).await.unwrap();
        logging::log!("Created config file");
        conf
    } else {
        logging::log!("Config file not found");
        return;
    };

    println!("Config: {:?}", node_conf);

    let peer_state = server::PeerState::new(&node_conf.peers);

    // Setting get_configuration(None) means we'll be using cargo-leptos's env values
    // For deployment these variables are:
    // <https://github.com/leptos-rs/start-axum#executing-a-server-on-a-remote-machine-without-the-toolchain>
    // Alternately a file can be specified such as Some("Cargo.toml")
    // The file would need to be included with the executable when moved to deployment
    let conf = get_configuration(Some("Cargo.toml")).await.unwrap();
    let mut leptos_options = conf.leptos_options;
    let mut addr = leptos_options.site_addr;
    addr.set_port(node_conf.listen_port);
    leptos_options.site_addr = addr;
    let routes = generate_route_list(App);
    //let state = State { leptos_options };
    // build our application with a route
    let app = Router::new()
        .leptos_routes(&leptos_options, routes, App)
        .nest("/peer/", server::get_peer_router(peer_state.clone()))
        .fallback(file_and_error_handler)
        .with_state(leptos_options)
        .layer(CompressionLayer::new().quality(CompressionLevel::Fastest));
    let token = tokio_util::sync::CancellationToken::new();
    let mut tasks = tokio::task::JoinSet::new();
    if args.run_tasks {
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
    }

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    let server = tasks.spawn(async move {
        logging::log!("listening on http://{}", &listener.local_addr()?);
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
            server.abort();
            logging::log!("Shutting down");
            tokio::select! {
                _ = async move {while tasks.join_next().await.is_some() {}} => {},
                _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {}
            }
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
