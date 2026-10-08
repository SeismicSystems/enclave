//! Derivation of the per-consumer peer lists from the parsed peer inputs, and
//! the one peer rule that needs the node.
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
//! `[node].external_ip` is the address this machine is reached at: it decides
//! which bootnode entry names this node itself, and it is the address summit
//! advertises for consensus (`summit_advertised_addr`).
//!
//! Both arrive parsed (`tdx-init-config`'s [`Bootnode`] and an `IpAddr`), so
//! a malformed enode or IP has already failed the POST with `400`. What is
//! checked here needs the node: a node left with no usable bootnode whose
//! candidate root key the manifest does not pin would otherwise boot an
//! attestation service with no way to obtain `root_key`.

use crate::error::{Result, TdxInitError};
use seismic_custodian_ipc::candidate_tx_io_pk;
use std::net::SocketAddr;
use std::path::Path;
use tdx_init_config::{Bootnode, BootnodeHost, NodeConfig};
use tracing::info;

/// Port the attestation service serves `getWrappedRootKey` on
/// (`DEFAULT_ENDPOINT_PORT` in `bin/attestation-service`, which is a binary
/// crate — the constant can't be imported).
const ROOT_KEY_PEER_PORT: u16 = 7878;

// TODO: delete this constant and emit the bare IP once
// https://github.com/SeismicSystems/summit/pull/455 is merged and the image's
// summit pin carries it. summit's `--ip` then takes an address without a port
// and pairs it with its own `--port`, so `summit_advertised_addr` returns the
// validated `IpAddr`, `summit.env` carries a host, and neither the port nor the
// IPv6 bracketing it forces has to live here.
/// Port summit accepts consensus connections on. Must equal the `--port` its
/// systemd unit passes, since the two halves of `summit_advertised_addr` are
/// what the node listens on and what it tells the cohort to dial.
const SUMMIT_CONSENSUS_PORT: u16 = 18551;

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
    pub peer_enodes: Vec<Bootnode>,
    /// Where the attestation service fetches `root_key` when the local
    /// custodian starts without one (`attestation.env`'s
    /// `SEISMIC_ROOT_KEY_PEERS`): `http://<host>:7878` per peer host, deduped
    /// by URL, since one host serves one root key however many enodes it runs.
    pub root_key_urls: Vec<String>,
}

/// Render this node's peer lists from the bootnodes. The node's own enode
/// (host == `external_ip`) is dropped — after the founding ceremony the
/// persisted bootnode set includes every founding node, this one included, and
/// a node has no reason to reach itself. A node that does not hold the pinned
/// candidate ([`holds_pinned_candidate`]) must end up with at least one peer,
/// or it has no source for `root_key`.
pub fn derive_peer_lists(
    node: &NodeConfig,
    bootnodes: &[Bootnode],
    holds_pinned_candidate: bool,
) -> Result<PeerLists> {
    let mut derived = PeerLists {
        peer_enodes: Vec::new(),
        root_key_urls: Vec::new(),
    };
    for enode in bootnodes {
        let host = enode.host();
        // A DNS host never matches: tdx-init does not resolve names.
        if *host == BootnodeHost::Ip(node.external_ip) {
            continue;
        }
        derived.peer_enodes.push(enode.clone());
        let peer = format!("http://{host}:{ROOT_KEY_PEER_PORT}");
        if !derived.root_key_urls.contains(&peer) {
            derived.root_key_urls.push(peer);
        }
    }
    info!(
        "peer config valid: {} bootnode(s), {} peer enode(s), {} root-key peer(s), external_ip={}",
        bootnodes.len(),
        derived.peer_enodes.len(),
        derived.root_key_urls.len(),
        node.external_ip,
    );
    if derived.root_key_urls.is_empty() {
        if !holds_pinned_candidate {
            return Err(TdxInitError::InvalidPeers(
                "this node must fetch root_key from a peer, since the manifest does not pin \
                 its custodian's current candidate root key, but [network].bootnodes names no \
                 machine other than this node. List a peer that holds root_key. If no other \
                 node holds it, the pinned candidate was lost to a custodian restart or a \
                 reboot: found the network again."
                    .to_string(),
            ));
        }
        info!(
            "[network].bootnodes names no machine other than this node, which holds the \
             pinned root key: it founds the network, and reth starts with neither bootnodes \
             nor trusted peers"
        );
    }
    Ok(derived)
}

/// Whether the custodian's candidate, as its candidate tx_io_pk file names it,
/// is the key the manifest pins. A missing file reads as `false`: the harvest
/// cannot quote a box without one, so assemble cannot have pinned it.
pub fn holds_pinned_candidate(candidate_tx_io_pk_path: &Path, pin: &[u8; 33]) -> Result<bool> {
    Ok(candidate_tx_io_pk::read(candidate_tx_io_pk_path)?
        .is_some_and(|candidate| candidate == *pin))
}

/// The consensus address this node advertises to the cohort (`summit.env`'s
/// `SUMMIT_ADVERTISED_ADDR`, spliced into summit's `--ip`): `external_ip` at
/// the consensus port.
///
/// An address is not part of validator identity — summit's genesis carries the
/// founding cohort's addresses outside its config digest, and a validator's
/// consensus-state record holds none at all. Each node instead signs its own
/// address and gossips that record, so this value is what the whole cohort
/// dials this node on. Delivering it keeps that declaration sourced from the
/// operator's descriptor, the same field reth advertises via `--nat extip`: a
/// joining node has no genesis entry to read its address from, and would
/// otherwise resolve one by asking public IP-echo services. It also keeps a
/// founding node truthful across an address change, which its founding-era
/// genesis entry cannot follow.
///
/// A `SocketAddr` rather than a formatted string: its `Display` brackets IPv6,
/// which is the form summit parses.
pub fn summit_advertised_addr(node: &NodeConfig) -> SocketAddr {
    SocketAddr::new(node.external_ip, SUMMIT_CONSENSUS_PORT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tdx_init_config::DomainConfig;

    fn node(external_ip: &str) -> NodeConfig {
        NodeConfig {
            external_ip: external_ip.parse().unwrap(),
            domain: DomainConfig {
                email: "ops@example.com".parse().unwrap(),
                name: "node1.example.com".parse().unwrap(),
            },
        }
    }

    /// Peer derivation for a node whose candidate the manifest does not pin.
    fn unpinned(node: &NodeConfig, bootnodes: &[Bootnode]) -> Result<PeerLists> {
        derive_peer_lists(node, bootnodes, false)
    }

    /// A valid enode at `host_port`, with node id `id` repeated 128 times.
    fn enode_with_id(id: char, host_port: &str) -> Bootnode {
        format!("enode://{}@{host_port}", id.to_string().repeat(128))
            .parse()
            .unwrap()
    }

    fn enode(host_port: &str) -> Bootnode {
        enode_with_id('a', host_port)
    }

    #[test]
    fn derives_peers_from_bootnodes() {
        let peers = unpinned(
            &node("203.0.113.7"),
            &[enode("10.0.0.1:30303"), enode("10.0.0.2:30303")],
        )
        .unwrap()
        .root_key_urls;
        assert_eq!(peers, vec!["http://10.0.0.1:7878", "http://10.0.0.2:7878"]);
    }

    #[test]
    fn drops_own_enode() {
        let peers = unpinned(
            &node("10.0.0.1"),
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
        let peers = unpinned(
            &node("2001:db8::1"),
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
        let peers = unpinned(&node("10.0.0.1"), &[enode("[2001:db8::1]:30303")])
            .unwrap()
            .root_key_urls;
        assert_eq!(peers, vec!["http://[2001:db8::1]:7878"]);
    }

    #[test]
    fn keeps_dns_peer_hosts() {
        let peers = unpinned(&node("10.0.0.1"), &[enode("node2.example.com:30303")])
            .unwrap()
            .root_key_urls;
        assert_eq!(peers, vec!["http://node2.example.com:7878"]);
    }

    #[test]
    fn dedupes_repeated_hosts() {
        // Two enodes on one host collapse to a single root-key URL, but both
        // stay peer enodes: reth keys peers by node id, not by address.
        let second = enode_with_id('b', "10.0.0.2:30303");
        let derived = unpinned(
            &node("10.0.0.1"),
            &[enode("10.0.0.2:30303"), second.clone()],
        )
        .unwrap();
        assert_eq!(derived.root_key_urls, vec!["http://10.0.0.2:7878"]);
        assert_eq!(derived.peer_enodes, vec![enode("10.0.0.2:30303"), second]);
    }

    #[test]
    fn keeps_peer_enodes_in_order_without_self() {
        let derived = unpinned(
            &node("10.0.0.1"),
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
    fn the_pinned_box_may_have_no_bootnodes() {
        // The pinned box at founding has no peers to dial and keeps its
        // candidate root_key.
        let derived = derive_peer_lists(&node("10.0.0.1"), &[], true).unwrap();
        assert!(derived.root_key_urls.is_empty());
        assert!(derived.peer_enodes.is_empty());

        let derived =
            derive_peer_lists(&node("10.0.0.1"), &[enode("10.0.0.1:30303")], true).unwrap();
        assert!(derived.root_key_urls.is_empty());
        assert!(derived.peer_enodes.is_empty());
    }

    #[test]
    fn rejects_an_unpinned_node_without_a_peer() {
        for bootnodes in [vec![], vec![enode("10.0.0.1:30303")]] {
            let err = unpinned(&node("10.0.0.1"), &bootnodes).unwrap_err();
            assert!(
                matches!(&err, TdxInitError::InvalidPeers(msg) if msg.contains("fetch root_key")),
                "{bootnodes:?}: {err}"
            );
        }
    }

    #[test]
    fn holds_the_pinned_candidate_only_when_the_file_names_the_pin() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("candidate-tx-io-pk");
        let pin = [0x02; 33];

        assert!(!holds_pinned_candidate(&path, &pin).unwrap(), "no file");
        candidate_tx_io_pk::write(&path, &[0x03; 33]).unwrap();
        assert!(!holds_pinned_candidate(&path, &pin).unwrap(), "another key");
        candidate_tx_io_pk::write(&path, &pin).unwrap();
        assert!(holds_pinned_candidate(&path, &pin).unwrap());
        std::fs::write(&path, "not json").unwrap();
        assert!(matches!(
            holds_pinned_candidate(&path, &pin),
            Err(TdxInitError::CandidateTxIoPk(_))
        ));
    }

    #[test]
    fn advertises_external_ip_at_the_consensus_port() {
        let addr = summit_advertised_addr(&node("203.0.113.7"));
        assert_eq!(addr.to_string(), "203.0.113.7:18551");
    }

    #[test]
    fn advertises_ipv6_bracketed() {
        // The address is handed to summit as text and parsed there as a socket
        // address, so an IPv6 host has to arrive bracketed.
        let addr = summit_advertised_addr(&node("2001:db8::7"));
        assert_eq!(addr.to_string(), "[2001:db8::7]:18551");
    }
}
