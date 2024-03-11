pub mod app;
pub mod domain;
pub mod error_template;
pub mod filterlist;
pub mod home_page;
pub mod ip_view;
pub mod rule;
#[cfg(feature = "ssr")]
pub mod server;
pub mod stats_view;
pub mod tasks;

#[cfg(feature = "ssr")]
use mimalloc::MiMalloc;
use serde::*;

#[cfg(feature = "ssr")]
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

const PAGE_SIZE: usize = 50;
pub mod source {
    use super::*;
    #[cfg_attr(feature = "ssr", derive(sqlx::Encode, sqlx::Decode))]
    #[derive(Serialize, Deserialize, Debug, Copy, Clone, PartialEq, Eq, Hash)]
    pub struct SourceId(i32);
}

#[derive(thiserror::Error, Debug)]
pub enum DbInitError {
    #[error("Sqlx error {0}")]
    SqlxError(String),
    #[error("Missing DATABASE_URL")]
    MissingDatabaseUrl(String),
}
#[cfg(feature = "ssr")]
impl From<sqlx::Error> for DbInitError {
    fn from(e: sqlx::Error) -> Self {
        Self::SqlxError(e.to_string())
    }
}

#[cfg(feature = "ssr")]
impl From<std::env::VarError> for DbInitError {
    fn from(e: std::env::VarError) -> Self {
        Self::MissingDatabaseUrl(e.to_string())
    }
}

#[cfg(feature = "ssr")]
pub mod fileserv;

#[cfg(feature = "hydrate")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn hydrate() {
    console_error_panic_hook::set_once();
    let _ = console_log::init_with_level(log::Level::Debug);
    log::info!("Hydrating");
    leptos::mount_to_body(crate::app::App);
    log::info!("Mounted");
    // leptos::leptos_dom::HydrationCtx::stop_hydrating();
}
