//! POST-time validation of the peer inputs and derivation of the per-consumer
//! peer lists.
//!
//! `[network].bootnodes` is the single source for the cohort's peer machines.
//! It feeds three consumers, in two renderings:
//!
//! - reth's `--bootnodes` and `--trusted-peers` both take the peer enodes, for
//!   different jobs: trusted peers are how the node reaches the cohort,
//!   bootnodes are how it reaches everyone the cohort list cannot name (the
//!   writer module renders both into `reth-p2p.env`).
//! - the attestation service's root-key fetch list takes the same machines as
//!   `http://<host>:7878`.
//!
//! Both renderings drop this node's own entry and come from one pass over the
//! input, so skew between them is unrepresentable and the `http://…:7878`
//! convention lives in exactly one place.
//!
//! Validation is structural, so a malformed enode or IP fails the deploy POST
//! with `400` rather than surfacing when reth parses its flags at boot and
//! crash-loops — likewise a non-genesis node left with no usable bootnode,
//! which would otherwise boot an attestation service with no way to obtain
//! `root_key`.

use crate::config::NodeConfig;
use crate::error::{Result, TdxInitError};
use std::net::IpAddr;
use tracing::{info, warn};

/// Number of hex chars in an enode node id: the 64-byte secp256k1 public key
/// (uncompressed, without the 0x04 prefix), hex-encoded.
const ENODE_ID_HEX_LEN: usize = 128;

/// Port the attestation service serves `getWrappedRootKey` on
/// (`DEFAULT_ENDPOINT_PORT` in `bin/attestation-service`, which is a binary
/// crate — the constant can't be imported).
const ROOT_KEY_PEER_PORT: u16 = 7878;

/// The cohort as this node's consumers need it: two renderings of the same
/// machines, built in one pass from `[network].bootnodes` so they cannot
/// disagree about who the cohort is. This node's own entry is dropped from
/// both — nothing here is a list this node uses to reach itself.
#[derive(Debug)]
pub struct PeerLists {
    /// The other founding nodes' enodes, in the order given. Both of reth's
    /// devp2p flags take this list (`reth-p2p.env`'s `RETH_BOOTNODES_FLAG` and
    /// `RETH_TRUSTED_PEERS_FLAG`), because they do different jobs with it:
    /// `--trusted-peers` is how the node reaches *the cohort* — direct RLPx
    /// dials, retried, exempt from reputation slashing — while `--bootnodes`
    /// seeds discv5, which is how it reaches everyone the list cannot name.
    /// Membership on this plane is open, so later joiners are exactly the peers
    /// no founding-era list could have held.
    pub peer_enodes: Vec<String>,
    /// Where the attestation service fetches `root_key` when the local
    /// custodian starts without one (`attestation.env`'s
    /// `SEISMIC_ROOT_KEY_PEERS`): `http://<host>:7878` per peer host, deduped
    /// by URL, since one host serves one root key however many enodes it runs.
    pub root_key_urls: Vec<String>,
}

/// Validate the peer inputs from the POSTed config and render this node's peer
/// lists from the bootnodes: `external_ip` must parse as an IP address and
/// every bootnode must be a well-formed `enode://` URL. The node's own enode
/// (host == `external_ip`) is dropped — after the founding ceremony the
/// persisted bootnode set includes every founding node, this one included, and
/// a node has no reason to reach itself. A non-genesis node must end up with at
/// least one peer, or it has no source for `root_key`.
pub fn validate_and_derive_peers(node: &NodeConfig, bootnodes: &[String]) -> Result<PeerLists> {
    let external_ip = parse_external_ip(&node.external_ip)?;
    let mut derived = PeerLists {
        peer_enodes: Vec::new(),
        root_key_urls: Vec::new(),
    };
    for enode in bootnodes {
        let host = parse_enode_host(enode)?;
        if is_self(host, external_ip) {
            continue;
        }
        derived.peer_enodes.push(enode.clone());
        let peer = format!("http://{host}:{ROOT_KEY_PEER_PORT}");
        if !derived.root_key_urls.contains(&peer) {
            derived.root_key_urls.push(peer);
        }
    }
    if !node.genesis_node && derived.root_key_urls.is_empty() {
        return Err(TdxInitError::InvalidPeers(
            "non-genesis node has no source for root_key: [network].bootnodes \
             must name at least one machine other than this node"
                .to_string(),
        ));
    }
    info!(
        "peer config valid: {} bootnode(s), {} peer enode(s), {} root-key peer(s), external_ip={}",
        bootnodes.len(),
        derived.peer_enodes.len(),
        derived.root_key_urls.len(),
        node.external_ip,
    );
    // Only a genesis node reaches this empty (a joiner without peers already
    // failed above), and its two readings look identical from here: correct at
    // founding, a stale peer list on any boot after joiners arrived.
    if derived.peer_enodes.is_empty() {
        warn!(
            "[network].bootnodes names no machine other than this node: reth starts with \
             neither bootnodes nor trusted peers, so this node joins no gossip mesh. \
             Expected for the genesis node at founding; on a later boot it means the \
             delivered peer list is stale."
        );
    }
    Ok(derived)
}

/// Check that `enode` matches `enode://<128 hex pubkey>@host:port` and return
/// the host. Host shape (IPv4/IPv6/DNS) is left to reth; we only require it
/// non-empty and the port to parse as a `u16`.
fn parse_enode_host(enode: &str) -> Result<&str> {
    let rest = enode.strip_prefix("enode://").ok_or_else(|| {
        TdxInitError::InvalidPeers(format!("bootnode {enode:?} must start with enode://"))
    })?;
    let (id, host_port) = rest.split_once('@').ok_or_else(|| {
        TdxInitError::InvalidPeers(format!(
            "bootnode {enode:?} is missing the '@' separating node id from host:port"
        ))
    })?;
    if id.len() != ENODE_ID_HEX_LEN || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(TdxInitError::InvalidPeers(format!(
            "bootnode {enode:?} pubkey must be {ENODE_ID_HEX_LEN} hex chars"
        )));
    }
    // rsplit so a bracketed IPv6 host ("[::1]:30303") keeps its inner colons.
    let (host, port) = host_port.rsplit_once(':').ok_or_else(|| {
        TdxInitError::InvalidPeers(format!("bootnode {enode:?} is missing ':port'"))
    })?;
    if host.is_empty() {
        return Err(TdxInitError::InvalidPeers(format!(
            "bootnode {enode:?} has an empty host"
        )));
    }
    port.parse::<u16>().map_err(|_| {
        TdxInitError::InvalidPeers(format!(
            "bootnode {enode:?} has a non-numeric port {port:?}"
        ))
    })?;
    Ok(host)
}

/// Check that `external_ip` parses as an IPv4 or IPv6 address.
fn parse_external_ip(ip: &str) -> Result<IpAddr> {
    ip.parse::<IpAddr>().map_err(|_| {
        TdxInitError::InvalidPeers(format!("external_ip {ip:?} is not a valid IP address"))
    })
}

/// Whether an enode host names this node itself. Compared as parsed
/// `IpAddr`s so equivalent textual forms match (`[2001:0db8::1]` vs
/// `2001:db8::1`); a DNS host never matches — tdx-init does not resolve.
fn is_self(host: &str, external_ip: IpAddr) -> bool {
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    bare.parse::<IpAddr>() == Ok(external_ip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DomainConfig;

    fn node(external_ip: &str, genesis_node: bool) -> NodeConfig {
        NodeConfig {
            external_ip: external_ip.to_string(),
            genesis_node,
            domain: DomainConfig {
                email: "ops@example.com".to_string(),
                name: "node1.example.com".to_string(),
            },
        }
    }

    /// A syntactically valid enode at `host_port` (128-hex pubkey).
    fn enode(host_port: &str) -> String {
        format!("enode://{}@{host_port}", "a".repeat(ENODE_ID_HEX_LEN))
    }

    #[test]
    fn derives_peers_from_bootnodes() {
        let peers = validate_and_derive_peers(
            &node("203.0.113.7", false),
            &[enode("10.0.0.1:30303"), enode("10.0.0.2:30303")],
        )
        .unwrap()
        .root_key_urls;
        assert_eq!(peers, vec!["http://10.0.0.1:7878", "http://10.0.0.2:7878"]);
    }

    #[test]
    fn drops_own_enode() {
        let peers = validate_and_derive_peers(
            &node("10.0.0.1", false),
            &[enode("10.0.0.1:30303"), enode("10.0.0.2:30303")],
        )
        .unwrap()
        .root_key_urls;
        assert_eq!(peers, vec!["http://10.0.0.2:7878"]);
    }

    #[test]
    fn drops_own_enode_by_ip_equality_not_string_equality() {
        // A non-canonical IPv6 spelling of this node's own address still
        // counts as self.
        let peers = validate_and_derive_peers(
            &node("2001:db8::1", false),
            &[
                enode("[2001:0db8:0:0:0:0:0:1]:30303"),
                enode("10.0.0.2:30303"),
            ],
        )
        .unwrap()
        .root_key_urls;
        assert_eq!(peers, vec!["http://10.0.0.2:7878"]);
    }

    #[test]
    fn keeps_bracketed_ipv6_peer_hosts() {
        let peers =
            validate_and_derive_peers(&node("10.0.0.1", false), &[enode("[2001:db8::1]:30303")])
                .unwrap()
                .root_key_urls;
        assert_eq!(peers, vec!["http://[2001:db8::1]:7878"]);
    }

    #[test]
    fn keeps_dns_peer_hosts() {
        let peers = validate_and_derive_peers(
            &node("10.0.0.1", false),
            &[enode("node2.example.com:30303")],
        )
        .unwrap()
        .root_key_urls;
        assert_eq!(peers, vec!["http://node2.example.com:7878"]);
    }

    #[test]
    fn dedupes_repeated_hosts() {
        // Two enodes on one host collapse to a single root-key URL, but both
        // stay peer enodes: reth keys peers by node id, not by address.
        let mut second = enode("10.0.0.2:30303");
        second = second.replacen('a', "b", 1);
        let derived = validate_and_derive_peers(
            &node("10.0.0.1", false),
            &[enode("10.0.0.2:30303"), second.clone()],
        )
        .unwrap();
        assert_eq!(derived.root_key_urls, vec!["http://10.0.0.2:7878"]);
        assert_eq!(derived.peer_enodes, vec![enode("10.0.0.2:30303"), second]);
    }

    #[test]
    fn keeps_peer_enodes_in_order_without_self() {
        let derived = validate_and_derive_peers(
            &node("10.0.0.1", false),
            &[
                enode("10.0.0.1:30303"),
                enode("10.0.0.2:30303"),
                enode("node3.example.com:30303"),
            ],
        )
        .unwrap();
        assert_eq!(
            derived.peer_enodes,
            vec![enode("10.0.0.2:30303"), enode("node3.example.com:30303")]
        );
    }

    #[test]
    fn genesis_node_may_have_no_bootnodes() {
        // The greenfield genesis node has no peers to dial and mints
        // root_key itself.
        let derived = validate_and_derive_peers(&node("10.0.0.1", true), &[]).unwrap();
        assert!(derived.root_key_urls.is_empty());
        assert!(derived.peer_enodes.is_empty());
    }

    #[test]
    fn rejects_joiner_without_bootnodes() {
        let err = validate_and_derive_peers(&node("10.0.0.1", false), &[]).unwrap_err();
        assert!(matches!(err, TdxInitError::InvalidPeers(_)));
        assert!(err.to_string().contains("root_key"), "{err}");
    }

    #[test]
    fn rejects_joiner_whose_only_bootnode_is_itself() {
        let err = validate_and_derive_peers(&node("10.0.0.1", false), &[enode("10.0.0.1:30303")])
            .unwrap_err();
        assert!(err.to_string().contains("root_key"), "{err}");
    }

    #[test]
    fn accepts_uppercase_hex_node_id() {
        let id = "AbCdEf".repeat(ENODE_ID_HEX_LEN / 6) + &"0".repeat(ENODE_ID_HEX_LEN % 6);
        assert_eq!(id.len(), ENODE_ID_HEX_LEN);
        let enode = format!("enode://{id}@example.com:30303");
        validate_and_derive_peers(&node("10.0.0.1", false), &[enode]).unwrap();
    }

    #[test]
    fn rejects_missing_enode_scheme() {
        let bad = enode("10.0.0.1:30303").replace("enode://", "");
        let err = validate_and_derive_peers(&node("10.0.0.1", false), &[bad]).unwrap_err();
        assert!(matches!(err, TdxInitError::InvalidPeers(_)));
        assert!(err.to_string().contains("enode://"), "{err}");
    }

    #[test]
    fn rejects_short_node_id() {
        let id = "a".repeat(ENODE_ID_HEX_LEN - 1);
        let bad = format!("enode://{id}@10.0.0.1:30303");
        let err = validate_and_derive_peers(&node("10.0.0.1", false), &[bad]).unwrap_err();
        assert!(err.to_string().contains("hex chars"), "{err}");
    }

    #[test]
    fn rejects_non_hex_node_id() {
        let id = "z".repeat(ENODE_ID_HEX_LEN);
        let bad = format!("enode://{id}@10.0.0.1:30303");
        let err = validate_and_derive_peers(&node("10.0.0.1", false), &[bad]).unwrap_err();
        assert!(err.to_string().contains("hex chars"), "{err}");
    }

    #[test]
    fn rejects_missing_at_separator() {
        let bad = format!("enode://{}", "a".repeat(ENODE_ID_HEX_LEN));
        let err = validate_and_derive_peers(&node("10.0.0.1", false), &[bad]).unwrap_err();
        assert!(err.to_string().contains("'@'"), "{err}");
    }

    #[test]
    fn rejects_missing_port() {
        let bad = enode("10.0.0.1");
        let err = validate_and_derive_peers(&node("10.0.0.1", false), &[bad]).unwrap_err();
        assert!(err.to_string().contains(":port"), "{err}");
    }

    #[test]
    fn rejects_non_numeric_port() {
        let bad = enode("10.0.0.1:notaport");
        let err = validate_and_derive_peers(&node("10.0.0.1", false), &[bad]).unwrap_err();
        assert!(err.to_string().contains("port"), "{err}");
    }

    #[test]
    fn rejects_empty_host() {
        let bad = enode(":30303");
        let err = validate_and_derive_peers(&node("10.0.0.1", false), &[bad]).unwrap_err();
        assert!(err.to_string().contains("empty host"), "{err}");
    }

    #[test]
    fn rejects_invalid_external_ip() {
        let err = validate_and_derive_peers(&node("not.an.ip", true), &[enode("10.0.0.1:30303")])
            .unwrap_err();
        assert!(matches!(err, TdxInitError::InvalidPeers(_)));
        assert!(err.to_string().contains("valid IP"), "{err}");
    }
}
