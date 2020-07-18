use serde::*;
use std::str::FromStr;

#[derive(Default, Debug)]
pub struct InvalidDomain {}

impl std::error::Error for InvalidDomain {}

impl std::fmt::Display for InvalidDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Serialize, Deserialize, PartialEq, PartialOrd, Eq, Ord, Hash, Clone, Debug)]
pub struct Domain(Box<str>);

impl Domain {
    pub fn iter_parent_domains(&self) -> impl Iterator<Item = Domain> + '_ {
        self.0
            .match_indices(|c| c == '.')
            .map(move |(i, _)| self.0.split_at(i + 1).1)
            .filter(|domain| domain.contains('.'))
            .inspect(|domain| debug_assert!(domain.parse::<Domain>().is_ok())) // Check that all the returned parent domains would be valid
            .map(move |domain| Domain(domain.to_string().into_boxed_str()))
    }
}

impl FromStr for Domain {
    type Err = InvalidDomain;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() > 253 {
            return Err(Self::Err::default());
        }
        let mut label_count = 0;
        for label in s.split('.') {
            label_count += 1;
            if label_count > 127
                || label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                return Err(Self::Err::default());
            }
        }
        if label_count <= 1
            || s.rsplit('.')
                .next()
                .unwrap_or(s)
                .chars()
                .all(|c| c == '.' || c.is_digit(10))
        {
            return Err(Self::Err::default());
        }
        Ok(Domain(s.to_ascii_lowercase().into_boxed_str()))
    }
}

impl std::ops::Deref for Domain {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::fmt::Display for Domain {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[test]
fn normal_is_ok() {
    assert!("www.google.com".parse::<Domain>().is_ok())
}

#[test]
fn label_starts_with_dash_is_invalid() {
    assert!("www.-google.com".parse::<Domain>().is_err())
}

#[test]
fn label_ends_with_dash_is_invalid() {
    assert!("www.google-.com".parse::<Domain>().is_err())
}

#[test]
fn domain_with_star_is_invalid() {
    assert!("*.google.com".parse::<Domain>().is_err())
}

#[test]
fn with_example_invalids() {
    let invalid = ["-fsecure.com", "-rotation.de", ".pw", ".tk"];
    for domain in &invalid {
        assert!(domain.parse::<Domain>().is_err())
    }
}

#[test]
fn iter_parent_domains() {
    let domain = "adwords.l.google.com".parse::<Domain>().unwrap();
    let expected = vec![
        "l.google.com".parse::<Domain>().unwrap(),
        "google.com".parse().unwrap(),
    ];
    assert_eq!(
        expected,
        domain.iter_parent_domains().collect::<Vec<Domain>>()
    )
}
