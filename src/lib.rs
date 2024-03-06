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
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, PartialOrd, Eq, Ord, Hash)]
#[serde(transparent)]
pub struct FilterListUrl {
    url: Arc<url::Url>,
}

impl std::ops::Deref for FilterListUrl {
    type Target = url::Url;
    fn deref(&self) -> &Self::Target {
        self.url.as_ref()
    }
}

impl From<url::Url> for FilterListUrl {
    fn from(url: url::Url) -> Self {
        Self { url: url.into() }
    }
}

impl FromStr for FilterListUrl {
    type Err = url::ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(url::Url::parse(s)?.into())
    }
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FilterListType {
    Adblock,
    DomainBlocklist,
    DomainAllowlist,
    IPBlocklist,
    IPAllowlist,
    IPNetBlocklist,
    DenyHosts,
    RegexAllowlist,
    RegexBlocklist,
    Hostfile,
    PrivacyBadger,
}

impl FilterListType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Adblock => "Adblock",
            Self::DomainBlocklist => "DomainBlocklist",
            Self::DomainAllowlist => "DomainAllowlist",
            Self::IPBlocklist => "IPBlocklist",
            Self::IPAllowlist => "IPAllowlist",
            Self::IPNetBlocklist => "IPNetBlocklist",
            Self::DenyHosts => "DenyHosts",
            Self::RegexAllowlist => "RegexAllowlist",
            Self::RegexBlocklist => "RegexBlocklist",
            Self::Hostfile => "Hostfile",
            Self::PrivacyBadger => "PrivacyBadger",
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
            "DomainAllowlist" => Ok(Self::DomainAllowlist),
            "IPBlocklist" => Ok(Self::IPBlocklist),
            "IPAllowlist" => Ok(Self::IPAllowlist),
            "IPNetBlocklist" => Ok(Self::IPNetBlocklist),
            "DenyHosts" => Ok(Self::DenyHosts),
            "RegexAllowlist" => Ok(Self::RegexAllowlist),
            "RegexBlocklist" => Ok(Self::RegexBlocklist),
            "Hostfile" => Ok(Self::Hostfile),
            "PrivacyBadger" => Ok(Self::PrivacyBadger),
            _ => Err(InvalidFilterListTypeError),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(into = "Vec<(FilterListUrl, FilterListRecord)>")]
#[serde(from = "Vec<(FilterListUrl, FilterListRecord)>")]
pub struct FilterListMap(
    pub std::collections::BTreeMap<FilterListUrl, FilterListRecord>,
    // Just so it is consistently ordered
);

impl From<FilterListMap> for Vec<(FilterListUrl, FilterListRecord)> {
    fn from(val: FilterListMap) -> Self {
        val.0.into_iter().collect()
    }
}
impl From<Vec<(FilterListUrl, FilterListRecord)>> for FilterListMap {
    fn from(v: Vec<(FilterListUrl, FilterListRecord)>) -> Self {
        Self(v.into_iter().collect())
    }
}

#[cfg(feature = "ssr")]
pub mod fileserv;

#[cfg(feature = "hydrate")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn hydrate() {
    use crate::app::*;
    console_error_panic_hook::set_once();
    let _ = console_log::init_with_level(log::Level::Debug);
    // leptos::mount_to_body(App);
    leptos::leptos_dom::HydrationCtx::stop_hydrating();
}
