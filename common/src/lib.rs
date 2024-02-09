use serde::*;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, PartialOrd, Eq, Ord)]
pub struct FilterListRecord {
    pub name: String,
    pub url: String,
    pub author: String,
    pub license: String,
    pub expires: u64,
    pub list_type: FilterListType,
}

impl FilterListRecord {
    pub fn from_type(list_type: FilterListType) -> Self {
        Self {
            name: Default::default(),
            url: Default::default(),
            author: Default::default(),
            license: Default::default(),
            expires: Default::default(),
            list_type,
        }
    }
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, PartialOrd, Eq, Ord)]
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
