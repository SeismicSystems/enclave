//! The two `[node.domain]` values, as types that only hold a validated string.
//!
//! Both come from the untrusted operator and reach root-run code on the node
//! as plain text: tdx-init writes them unquoted into `domain.env`, and the
//! image's TLS proxy puts the name in its config and the email in its ACME
//! registration. The check sits on the type rather than in a handler that
//! might forget it: serde runs it while the POST is parsed, and nothing
//! downstream can hold a raw string.
//!
//! The check is hand-written and deliberately stricter than the standards. Its
//! job is to admit only characters that mean nothing to any consumer (a shell,
//! a config parser, an argv), so no consumer has to quote or escape
//! correctly. The libraries implement the standards, which are looser:
//!
//! - a URL host (the `url` crate) admits `;`, `$`, `(`, backticks and braces,
//!   has no label length limit, and drops a newline instead of rejecting it;
//! - an RFC 5322 or HTML5 email (`email_address`, `validator`) admits `$`,
//!   backticks, `/` and `{` before the `@`, and RFC 5322 also quoted strings;
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
/// RFC 5321's limit on the part of a [`PlainEmail`] before the `@`.
const MAX_EMAIL_LOCAL_PART_LEN: usize = 64;

/// A hostname per RFC 1123, the letters-digits-hyphen subset of DNS names
/// (whose labels may hold any byte): dot-separated labels of ASCII letters,
/// digits and `-`, each 1 to 63 characters and neither starting nor ending
/// with `-`, at most 253 characters in all, with no trailing dot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Hostname(String);

/// An email address with a plain local part: `<local>@<Hostname>`, the local
/// part 1 to 64 characters of ASCII letters, digits and `.` `_` `+` `-`, not
/// starting with `-` or `.`. It is the ACME registration contact.
///
/// Plain as opposed to the quoted and punctuated local parts RFC 5322 allows,
/// which are exactly the characters that mean something to a shell or a
/// config parser, and no operator needs them for an ACME contact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PlainEmail(String);

/// Why a string is not a [`Hostname`] or a [`PlainEmail`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidDomain(String);

impl fmt::Display for InvalidDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for InvalidDomain {}

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
    type Error = InvalidDomain;

    fn try_from(name: String) -> Result<Self, InvalidDomain> {
        check_hostname(&name)
            .map_err(|why| InvalidDomain(format!("domain name {name:?} {why}")))?;
        Ok(Self(name))
    }
}

impl TryFrom<String> for PlainEmail {
    type Error = InvalidDomain;

    fn try_from(email: String) -> Result<Self, InvalidDomain> {
        let invalid = |why: &str| InvalidDomain(format!("domain email {email:?} {why}"));
        let (local, domain) = email.split_once('@').ok_or_else(|| invalid("has no '@'"))?;
        if local.is_empty() || local.len() > MAX_EMAIL_LOCAL_PART_LEN {
            return Err(invalid(&format!(
                "must have a local part of 1 to {MAX_EMAIL_LOCAL_PART_LEN} characters"
            )));
        }
        if !local
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
        {
            return Err(invalid(
                "may hold only ASCII letters, digits, '.', '_', '+' and '-' before the '@'",
            ));
        }
        if local.starts_with(['-', '.']) {
            return Err(invalid("must not start with '-' or '.'"));
        }
        check_hostname(domain).map_err(|why| invalid(&format!("has a domain that {why}")))?;
        Ok(Self(email))
    }
}

macro_rules! string_newtype {
    ($ty:ident) => {
        impl FromStr for $ty {
            type Err = InvalidDomain;

            fn from_str(s: &str) -> Result<Self, InvalidDomain> {
                s.to_string().try_into()
            }
        }

        impl From<$ty> for String {
            fn from(value: $ty) -> String {
                value.0
            }
        }

        impl AsRef<str> for $ty {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

string_newtype!(Hostname);
string_newtype!(PlainEmail);

#[cfg(test)]
mod tests {
    use super::*;

    /// What each test below must survive: shell metacharacters, a path
    /// separator, whitespace, a quote, and a line break that would start a new
    /// `domain.env` line.
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
    fn accepts_emails() {
        for email in [
            "ops@example.com",
            "first.last+certs@example.com",
            "ops_team-1@sub.example.com",
        ] {
            email.parse::<PlainEmail>().unwrap();
        }
    }

    #[test]
    fn rejects_malformed_emails() {
        for email in [
            "",
            "ops",
            "@example.com",
            "ops@",
            "ops@example.com.",
            "ops@@example.com",
            "-ops@example.com",
            ".ops@example.com",
            "ops@exa_mple.com",
            &format!("{}@example.com", "a".repeat(65)),
        ] {
            assert!(email.parse::<PlainEmail>().is_err(), "{email:?}");
        }
    }

    #[test]
    fn rejects_injection_in_the_email() {
        for bad in INJECTIONS {
            for email in [
                format!("ops{bad}@example.com"),
                format!("ops@example{bad}.com"),
                format!("ops@example.com{bad}"),
            ] {
                assert!(email.parse::<PlainEmail>().is_err(), "{email:?}");
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
