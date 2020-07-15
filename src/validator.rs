use std::str::FromStr;

#[derive(Default)]
pub struct InvalidDomain {}

#[derive(PartialEq, PartialOrd, Eq, Ord, Hash, Clone, Debug)]
pub struct Domain(String);

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
                || !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            {
                return Err(Self::Err::default());
            }
        }
        if label_count <= 1 || s.chars().all(|c| c == '.' || c.is_digit(10)) {
            return Err(Self::Err::default());
        }
        Ok(Domain(s.to_string()))
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
