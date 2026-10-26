//! A hostname, as a type that only holds a validated string.
//!
//! A bootnode's host may be one ([`crate::Bootnode`]). It comes from the
//! untrusted operator and reaches the node as plain text: tdx-init writes it
//! unquoted into env files, which systemd splices into reth's argv and the
//! attestation service reads as a fetch URL. The check sits on the type rather
//! than in a handler that might forget it: serde runs it while the POST is
//! parsed, and nothing downstream can hold a raw string.
//!
//! The check is hand-written and deliberately stricter than the standards. Its
//! job is to admit only characters that mean nothing to any consumer (a shell,
//! a config parser, an argv), so no consumer has to quote or escape
//! correctly. The libraries implement the standards, which are looser:
//!
//! - a URL host (the `url` crate) admits `;`, `$`, `(`, backticks and braces,
//!   has no label length limit, and drops a newline instead of rejecting it;
//! - a DNS name (`hickory-proto`) admits nearly any byte in a label.
//!
//! The strict RFC 1123 rule fits in [`check_hostname`], and a small
//! dependency for it would add supply-chain surface to a binary in the
//! measured image.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// RFC 1035's limit on a [`Hostname`]'s text form, without the trailing dot.
const MAX_HOSTNAME_LEN: usize = 253;
/// RFC 1035's limit on each dot-separated label of a [`Hostname`].
const MAX_HOSTNAME_LABEL_LEN: usize = 63;

/// A hostname per RFC 1123, the letters-digits-hyphen subset of DNS names
/// (whose labels may hold any byte): dot-separated labels of ASCII letters,
/// digits and `-`, each 1 to 63 characters and neither starting nor ending
/// with `-`, at most 253 characters in all, with no trailing dot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Hostname(String);

/// Why a string is not a [`Hostname`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidHostname(String);

impl fmt::Display for InvalidHostname {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for InvalidHostname {}

fn check_hostname(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("is empty".to_string());
    }
    if name.len() > MAX_HOSTNAME_LEN {
        return Err(format!("is longer than {MAX_HOSTNAME_LEN} characters"));
    }
    for label in name.split('.') {
        if label.is_empty() {
            return Err("has an empty label".to_string());
        }
        if label.len() > MAX_HOSTNAME_LABEL_LEN {
            return Err(format!(
                "has a label longer than {MAX_HOSTNAME_LABEL_LEN} characters"
            ));
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err("may hold only ASCII letters, digits, '-' and '.'".to_string());
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(format!(
                "has a label {label:?} that starts or ends with '-'"
            ));
        }
    }
    Ok(())
}

impl TryFrom<String> for Hostname {
    type Error = InvalidHostname;

    fn try_from(name: String) -> Result<Self, InvalidHostname> {
        check_hostname(&name).map_err(|why| InvalidHostname(format!("hostname {name:?} {why}")))?;
        Ok(Self(name))
    }
}

impl FromStr for Hostname {
    type Err = InvalidHostname;

    fn from_str(s: &str) -> Result<Self, InvalidHostname> {
        s.to_string().try_into()
    }
}

impl From<Hostname> for String {
    fn from(value: Hostname) -> String {
        value.0
    }
}

impl AsRef<str> for Hostname {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Hostname {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What each test below must survive: shell metacharacters, a path
    /// separator, whitespace, a quote, and a line break that would start a new
    /// env-file line.
    const INJECTIONS: [&str; 7] = [";", "$(", "`", "/", "\n", " ", "\""];

    #[test]
    fn accepts_hostnames() {
        for name in [
            "node1.example.com",
            "localhost",
            "a-b.c-d.example",
            "NODE1.Example.COM",
            "1.example.com",
        ] {
            name.parse::<Hostname>().unwrap();
        }
        let longest = [&"a".repeat(63); 4].map(String::as_str).join(".");
        assert_eq!(longest.len(), 255);
        longest[2..].parse::<Hostname>().unwrap();
    }

    #[test]
    fn rejects_malformed_hostnames() {
        for name in [
            "",
            ".",
            "example.com.",
            ".example.com",
            "a..b",
            "-a.example.com",
            "a-.example.com",
            "a_b.example.com",
            "*.example.com",
            "nöde.example.com",
            &format!("{}.com", "a".repeat(64)),
            &[&"a".repeat(63); 4].map(String::as_str).join(".")[1..],
        ] {
            assert!(name.parse::<Hostname>().is_err(), "{name:?}");
        }
    }

    #[test]
    fn rejects_injection_in_the_name() {
        for bad in INJECTIONS {
            for name in [
                format!("node1{bad}example.com"),
                format!("{bad}node1.example.com"),
                format!("node1.example.com{bad}"),
            ] {
                assert!(name.parse::<Hostname>().is_err(), "{name:?}");
            }
        }
    }

    #[test]
    fn displays_as_the_bare_string() {
        let name: Hostname = "node1.example.com".parse().unwrap();
        assert_eq!(String::from(name.clone()), "node1.example.com");
        assert_eq!(name.to_string(), "node1.example.com");
    }
}
