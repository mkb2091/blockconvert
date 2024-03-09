pub mod app;
pub mod domain_import_view;
pub mod domain_view;
pub mod error_template;
pub mod home_page;
pub mod ip_view;
pub mod list_manager;
pub mod list_parser;
pub mod list_view;
pub mod rule_view;
#[cfg(feature = "ssr")]
pub mod server;
pub mod stats_view;

#[cfg(feature = "ssr")]
use mimalloc::MiMalloc;
use serde::*;
use std::convert::From;
use std::str::FromStr;
use std::sync::Arc;

#[cfg(feature = "ssr")]
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[derive(Serialize, Deserialize, Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct RuleId(i32);

#[derive(Serialize, Deserialize, Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct SourceId(i32);

#[derive(Serialize, Deserialize, Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct ListId(i32);

#[derive(Serialize, Deserialize, Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DomainId(i64);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FilterListRecord {
    pub name: Arc<str>,
    pub list_format: FilterListType,
    pub author: Arc<str>,
    pub license: Arc<str>,
    pub expires: std::time::Duration,
    pub last_updated: Option<chrono::DateTime<chrono::Utc>>,
    pub list_size: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, PartialOrd, Eq, Ord, Hash)]
#[serde(transparent)]
pub struct FilterListUrl {
    url: Arc<str>,
}

impl FilterListUrl {
    pub fn as_str(&self) -> &str {
        self.as_ref()
    }
    pub fn to_internal_path(&self) -> Option<std::path::PathBuf> {
        if self.as_str().starts_with("internal/") {
            Some(std::path::PathBuf::from(self.as_str()))
        } else {
            None
        }
    }
}

impl std::ops::Deref for FilterListUrl {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        self.url.as_ref()
    }
}

impl FromStr for FilterListUrl {
    type Err = url::ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "internal/blocklist.txt" | "internal/block_ips.txt" | "internal/allowlist.txt" => {
                Ok(Self { url: s.into() })
            }
            s => Ok(Self {
                url: url::Url::parse(s)?.as_str().into(),
            }),
        }
    }
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FilterListType {
    Adblock,
    DomainBlocklist,
    DomainBlocklistWithoutSubdomains,
    DomainAllowlist,
    IPBlocklist,
    IPAllowlist,
    IPNetBlocklist,
    DenyHosts,
    RegexAllowlist,
    RegexBlocklist,
    Hostfile,
}

impl FilterListType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Adblock => "Adblock",
            Self::DomainBlocklist => "DomainBlocklist",
            Self::DomainBlocklistWithoutSubdomains => "DomainBlocklistWithoutSubdomains",
            Self::DomainAllowlist => "DomainAllowlist",
            Self::IPBlocklist => "IPBlocklist",
            Self::IPAllowlist => "IPAllowlist",
            Self::IPNetBlocklist => "IPNetBlocklist",
            Self::DenyHosts => "DenyHosts",
            Self::RegexAllowlist => "RegexAllowlist",
            Self::RegexBlocklist => "RegexBlocklist",
            Self::Hostfile => "Hostfile",
        }
    }
}
#[derive(Debug, thiserror::Error)]
pub struct InvalidFilterListTypeError;

impl std::fmt::Display for InvalidFilterListTypeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Invalid FilterListType")
    }
}

impl std::str::FromStr for FilterListType {
    type Err = InvalidFilterListTypeError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Adblock" => Ok(Self::Adblock),
            "DomainBlocklist" => Ok(Self::DomainBlocklist),
            "DomainBlocklistWithoutSubdomains" => Ok(Self::DomainBlocklistWithoutSubdomains),
            "DomainAllowlist" => Ok(Self::DomainAllowlist),
            "IPBlocklist" => Ok(Self::IPBlocklist),
            "IPAllowlist" => Ok(Self::IPAllowlist),
            "IPNetBlocklist" => Ok(Self::IPNetBlocklist),
            "DenyHosts" => Ok(Self::DenyHosts),
            "RegexAllowlist" => Ok(Self::RegexAllowlist),
            "RegexBlocklist" => Ok(Self::RegexBlocklist),
            "Hostfile" => Ok(Self::Hostfile),
            _ => Err(InvalidFilterListTypeError),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FilterListMap(
    pub Vec<(FilterListUrl, FilterListRecord)>,
    // Just so it is consistently ordered
);

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
    // leptos::mount_to_body(App);
    leptos::leptos_dom::HydrationCtx::stop_hydrating();
}
