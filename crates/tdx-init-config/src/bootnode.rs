//! A `[network].bootnodes` entry, parsed.
//!
//! The entry comes from the untrusted operator and lands unquoted in env files
//! on the node, the whole URL as a reth flag and its host in a fetch URL. Each
//! part is therefore parsed to a shape that admits no whitespace, quote, `$`
//! or newline, and the host is kept as the address it names, so consumers
//! compare and render it without re-reading the text.

use crate::Hostname;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// Hex characters in an enode node id: the 64-byte secp256k1 public key
/// (uncompressed, without the 0x04 prefix), hex-encoded.
const ENODE_ID_HEX_LEN: usize = 128;

/// An [enode URL](https://ethereum.org/en/developers/docs/networking-layer/network-addresses/#enode)
/// of the form `enode://<pubkey>@<host>:<port>`, where:
///
/// - `pubkey` is 128 hex characters;
/// - `host` is a URL host: an IPv4 address, an IPv6 address in brackets
///   ([RFC 3986 §3.2.2](https://www.rfc-editor.org/rfc/rfc3986#section-3.2.2)),
///   or a [`Hostname`]. The spec names only IP hosts; reth, like geth, also
///   accepts a DNS name;
/// - `port` is a `u16`, split off at the last `:`, which the brackets keep
///   out of an IPv6 host.
///
/// Serializes as the original URL, which is what reth is handed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Bootnode {
    url: String,
    host: BootnodeHost,
}

/// The machine a [`Bootnode`] names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootnodeHost {
    Ip(IpAddr),
    Hostname(Hostname),
}

/// Why a string is not a [`Bootnode`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidBootnode(String);

impl fmt::Display for InvalidBootnode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for InvalidBootnode {}

impl Bootnode {
    pub fn host(&self) -> &BootnodeHost {
        &self.host
    }
}

/// The host as a URL takes it: an IPv6 address in brackets.
impl fmt::Display for BootnodeHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(IpAddr::V6(ip)) => write!(f, "[{ip}]"),
            Self::Ip(IpAddr::V4(ip)) => write!(f, "{ip}"),
            Self::Hostname(name) => write!(f, "{name}"),
        }
    }
}

impl TryFrom<String> for Bootnode {
    type Error = InvalidBootnode;

    fn try_from(url: String) -> Result<Self, InvalidBootnode> {
        let invalid = |why: String| InvalidBootnode(format!("bootnode {url:?} {why}"));
        let rest = url
            .strip_prefix("enode://")
            .ok_or_else(|| invalid("must start with enode://".to_string()))?;
        let (id, host_port) = rest.split_once('@').ok_or_else(|| {
            invalid("is missing the '@' separating node id from host:port".to_string())
        })?;
        if id.len() != ENODE_ID_HEX_LEN || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(invalid(format!(
                "pubkey must be {ENODE_ID_HEX_LEN} hex chars"
            )));
        }
        let (host, port) = host_port
            .rsplit_once(':')
            .ok_or_else(|| invalid("is missing ':port'".to_string()))?;
        if host.is_empty() {
            return Err(invalid("has an empty host".to_string()));
        }
        let parsed = match host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
            Some(bracketed) => bracketed
                .parse::<Ipv6Addr>()
                .ok()
                .map(|ip| BootnodeHost::Ip(ip.into())),
            None => match host.parse::<Ipv4Addr>() {
                Ok(ip) => Some(BootnodeHost::Ip(ip.into())),
                Err(_) => host.parse::<Hostname>().ok().map(BootnodeHost::Hostname),
            },
        };
        let host = parsed.ok_or_else(|| {
            invalid(format!(
                "host {host:?} is not an IPv4 address, a bracketed IPv6 address or a DNS name"
            ))
        })?;
        port.parse::<u16>()
            .map_err(|_| invalid(format!("has a non-numeric port {port:?}")))?;
        Ok(Self { url, host })
    }
}

impl FromStr for Bootnode {
    type Err = InvalidBootnode;

    fn from_str(s: &str) -> Result<Self, InvalidBootnode> {
        s.to_string().try_into()
    }
}

impl From<Bootnode> for String {
    fn from(bootnode: Bootnode) -> String {
        bootnode.url
    }
}

impl AsRef<str> for Bootnode {
    fn as_ref(&self) -> &str {
        &self.url
    }
}

impl fmt::Display for Bootnode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A syntactically valid enode at `host_port` (128-hex pubkey).
    fn enode(host_port: &str) -> String {
        format!("enode://{}@{host_port}", "a".repeat(ENODE_ID_HEX_LEN))
    }

    fn parse_err(url: &str) -> String {
        url.parse::<Bootnode>().unwrap_err().to_string()
    }

    #[test]
    fn parses_each_host_form() {
        let host = |hp: &str| enode(hp).parse::<Bootnode>().unwrap().host().clone();
        assert_eq!(
            host("10.0.0.1:30303"),
            BootnodeHost::Ip("10.0.0.1".parse().unwrap())
        );
        assert_eq!(
            host("[2001:db8::1]:30303"),
            BootnodeHost::Ip("2001:db8::1".parse().unwrap())
        );
        assert_eq!(
            host("node2.example.com:30303"),
            BootnodeHost::Hostname("node2.example.com".parse().unwrap())
        );
    }

    #[test]
    fn keeps_the_url_verbatim() {
        let url = enode("[2001:0db8:0:0:0:0:0:1]:30303");
        assert_eq!(url.parse::<Bootnode>().unwrap().to_string(), url);
    }

    #[test]
    fn renders_the_host_for_a_url() {
        let host = |hp: &str| enode(hp).parse::<Bootnode>().unwrap().host().to_string();
        assert_eq!(host("10.0.0.1:30303"), "10.0.0.1");
        assert_eq!(host("[2001:0db8::1]:30303"), "[2001:db8::1]");
        assert_eq!(host("node2.example.com:30303"), "node2.example.com");
    }

    #[test]
    fn equal_hosts_compare_by_value_not_spelling() {
        let host = |hp: &str| enode(hp).parse::<Bootnode>().unwrap().host().clone();
        assert_eq!(
            host("[2001:0db8:0:0:0:0:0:1]:30303"),
            host("[2001:db8::1]:30303")
        );
        assert_ne!(host("[2001:db8::1]:30303"), host("[2001:db8::2]:30303"));
    }

    #[test]
    fn accepts_uppercase_hex_node_id() {
        let id = "AbCdEf".repeat(ENODE_ID_HEX_LEN / 6) + &"0".repeat(ENODE_ID_HEX_LEN % 6);
        assert_eq!(id.len(), ENODE_ID_HEX_LEN);
        format!("enode://{id}@example.com:30303")
            .parse::<Bootnode>()
            .unwrap();
    }

    #[test]
    fn rejects_missing_enode_scheme() {
        let err = parse_err(&enode("10.0.0.1:30303").replace("enode://", ""));
        assert!(err.contains("enode://"), "{err}");
    }

    #[test]
    fn rejects_a_short_or_non_hex_node_id() {
        for id in [
            "a".repeat(ENODE_ID_HEX_LEN - 1),
            "z".repeat(ENODE_ID_HEX_LEN),
        ] {
            let err = parse_err(&format!("enode://{id}@10.0.0.1:30303"));
            assert!(err.contains("hex chars"), "{err}");
        }
    }

    #[test]
    fn rejects_missing_at_separator() {
        let err = parse_err(&format!("enode://{}", "a".repeat(ENODE_ID_HEX_LEN)));
        assert!(err.contains("'@'"), "{err}");
    }

    #[test]
    fn rejects_missing_port() {
        let err = parse_err(&enode("10.0.0.1"));
        assert!(err.contains(":port"), "{err}");
    }

    #[test]
    fn rejects_non_numeric_port() {
        let err = parse_err(&enode("10.0.0.1:notaport"));
        assert!(err.contains("non-numeric port"), "{err}");
    }

    #[test]
    fn rejects_empty_host() {
        let err = parse_err(&enode(":30303"));
        assert!(err.contains("empty host"), "{err}");
    }

    #[test]
    fn rejects_a_host_that_would_break_the_env_files() {
        for host in [
            "10.0.0.1\nRETH_NAT_FLAG=--nat extip:6.6.6.6\nX=10.0.0.1",
            "10.0.0.1 --http.api admin",
            "node2.example.com/evil",
            "$(reboot)",
            "[node2.example.com]",
            "[10.0.0.1]",
            "2001:db8::1",
        ] {
            let err = parse_err(&enode(&format!("{host}:30303")));
            assert!(err.contains("bracketed IPv6"), "{host:?}: {err}");
        }
    }
}
