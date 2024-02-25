pub mod app;
pub mod error_template;
pub mod list_manager;
pub mod list_parser;
#[cfg(feature = "ssr")]
pub mod server;
use serde::*;
use std::convert::{From, Into};
use std::sync::Arc;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FilterListRecord {
    pub name: Arc<str>,
    pub author: Arc<str>,
    pub license: Arc<str>,
    pub expires: std::time::Duration,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, PartialOrd, Eq, Ord, Hash)]
#[serde(into = "(Arc<url::Url>, FilterListType)")]
#[serde(from = "(Arc<url::Url>, FilterListType)")]
pub struct FilterListUrl {
    url: Arc<url::Url>,
    list_format: FilterListType,
}

impl Into<(Arc<url::Url>, FilterListType)> for FilterListUrl {
    fn into(self) -> (Arc<url::Url>, FilterListType) {
        (self.url, self.list_format)
    }
}
impl From<(Arc<url::Url>, FilterListType)> for FilterListUrl {
    fn from((url, list_format): (Arc<url::Url>, FilterListType)) -> Self {
        Self { url, list_format }
    }
}

impl std::ops::Deref for FilterListUrl {
    type Target = url::Url;
    fn deref(&self) -> &Self::Target {
        self.url.as_ref()
    }
}

impl FilterListUrl {
    pub fn new(url: url::Url, list_format: FilterListType) -> Self {
        Self {
            url: Arc::new(url),
            list_format,
        }
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
    DNSRPZ,
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
            Self::DNSRPZ => "DNSRPZ",
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
            "DNSRPZ" => Ok(Self::DNSRPZ),
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
impl std::convert::Into<Vec<(FilterListUrl, FilterListRecord)>> for FilterListMap {
    fn into(self) -> Vec<(FilterListUrl, FilterListRecord)> {
        self.0.into_iter().collect()
    }
}
impl std::convert::From<Vec<(FilterListUrl, FilterListRecord)>> for FilterListMap {
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
    leptos::mount_to_body(App);
}
