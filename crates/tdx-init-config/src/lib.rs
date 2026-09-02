//! The bootstrap config a Seismic node accepts at deploy time: the schema of
//! the TOML document POSTed to `tdx-init` on `:8080`, and the only definition
//! of that wire format.
//!
//! It is a crate of its own so both ends of the POST hold the same types: the
//! on-node `tdx-init` binary deserializes [`InitConfig`] and fans it out into
//! per-service config files, and deploy tooling constructs the same struct
//! rather than hand-assembling TOML. Nothing here does any work — no I/O, no
//! validation beyond serde's — so linking it costs a downstream crate nothing
//! but `serde`. Every semantic check (the manifest schema, the genesis
//! commitments, the peer derivation) lives in `tdx-init` itself, where the
//! POST is handled.
//!
//! `deny_unknown_fields` throughout: a field this build does not know is a
//! deploy tool and a node that disagree on the format, which must be a clean
//! `400` rather than a node silently running with defaults.

use serde::{Deserialize, Serialize};

/// Operator-supplied initialization config, received over HTTP at deploy
/// time and fanned out by tdx-init into per-component config files under
/// `/run/seismic/conf`.
///
/// Two sections, split by provenance: `[network]` is coordinator-produced —
/// a function of the network at POST time, never tailored to the recipient —
/// while `[node]` is this node only. Network-indexed is weaker than
/// cohort-identical: the bootnode set evolves as the network does (empty at
/// greenfield stage 1), so nodes configured at different times hold
/// different snapshots; only the manifest and the two genesis files must truly
/// match across the cohort — differing bytes there mean a different network.
/// Anything derivable from these is derived rather than delivered twice —
/// e.g. the root-key fetch peers come from `[network].bootnodes`
/// (`bin/tdx-init/src/peers.rs`), so there is no second list that could skew
/// from it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitConfig {
    /// Required: the attestation service reads `network-manifest.json` at startup to
    /// derive `network_id` and bind every attestation to it, and is fatal
    /// without it. A POST that omits `[network]` therefore 400s here rather
    /// than booting a node that crash-loops on the missing file. The deploy
    /// CLI merges the network-wide manifest into the per-node config at POST time.
    pub network: NetworkConfig,

    /// Per-node settings; see [`NodeConfig`].
    pub node: NodeConfig,
}

/// DNS name + contact email for the Let's Encrypt cert that fronts this
/// node's public RPC. Written by tdx-init to `domain.env` under
/// `/run/seismic/conf` as `DOMAIN_NAME=...` / `DOMAIN_EMAIL=...`, which
/// `setup-nginx-ssl` (seismic-images) sources before invoking certbot
/// for cert issuance and renewal.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainConfig {
    pub email: String,
    pub name: String,
}

/// The network's identity document, common to genesis and joining nodes.
///
/// `network_id = SHA-256(exact network-manifest.json bytes)`, so the manifest
/// travels base64-encoded (opaque bytes) rather than as an inline string:
/// tdx-init validates it at POST time and writes the decoded bytes verbatim
/// to `network-manifest.json` under `/run/seismic/conf`, never
/// parse-and-re-serialize. Validation lives in `bin/tdx-init/src/manifest.rs`
/// (schema in the `seismic-network-manifest` crate).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    /// base64 (standard alphabet) of the network-manifest.json bytes, as
    /// emitted by the deploy tool's manifest assembly step.
    ///
    /// This document is also what pins the other two `[network]` artifacts:
    /// `eth.genesis_hash` commits to the reth genesis carried in
    /// `reth_genesis_base64`, and `summit.genesis_config_digest` to the summit
    /// genesis in `summit_genesis_base64`. The three fields are therefore one
    /// assembled set rather than three independent values — pairing a manifest
    /// with a genesis it doesn't pin yields a node that can't join the cohort
    /// it claims to belong to (a reth genesis block hash its peers reject, or a
    /// summit `chain_domain` no handshake matches). tdx-init doesn't recompute
    /// either commitment in-process — that would need reth's own chain-spec
    /// parse path and summit's SSZ implementation — so it enforces the cheap
    /// fields the manifest duplicates for exactly this purpose (`eth.chain_id`,
    /// `summit.namespace`) and leaves the hashes to deploy, which verifies both
    /// before POSTing.
    pub manifest_base64: String,

    /// base64 encoding of the reth genesis JSON — the chain spec
    /// every node's reth boots from (`--chain
    /// /run/seismic/conf/reth-genesis.json`). Network-wide like the manifest,
    /// whose `eth.genesis_hash` pins its genesis block; required because a
    /// node booted without it has no chain spec and reth crash-loops.
    /// Validated at POST time against the manifest's `eth.chain_id`
    /// (`bin/tdx-init/src/reth_genesis.rs`) and written verbatim to
    /// `reth-genesis.json` under `/run/seismic/conf`.
    pub reth_genesis_base64: String,

    /// base64 encoding of the summit genesis TOML — the consensus-layer
    /// genesis every node's summit boots from
    /// (`--genesis-path /run/seismic/conf/summit-genesis.toml`). Network-wide
    /// like the reth genesis, and complete at delivery: the founding ceremony
    /// harvests the validator set into it before the POST, and the manifest's
    /// `summit.genesis_config_digest` pins the result. Required because a node
    /// booted without it has no consensus genesis and its summit blocks
    /// forever — late joiners need it just as much as the founders do.
    /// Validated structurally at POST time against the manifest's
    /// `summit.namespace` (`bin/tdx-init/src/summit_genesis.rs`) and written
    /// verbatim to `summit-genesis.toml` under `/run/seismic/conf`.
    pub summit_genesis_base64: String,

    /// Network-wide devp2p bootnodes, as `enode://<128 hex pubkey>@host:port`
    /// URLs — the single source for the cohort's peer machines. With this
    /// node's own entry dropped, they feed both of reth's devp2p flags
    /// (`reth-p2p.env`'s `RETH_BOOTNODES_FLAG` and `RETH_TRUSTED_PEERS_FLAG`)
    /// and, as `http://<host>:7878`, the attestation service's root-key fetch
    /// list (`attestation.env`); the rendering lives in
    /// `bin/tdx-init/src/peers.rs`, which also documents why reth gets the list
    /// twice. The field is required,
    /// but an empty list is valid on the genesis node only — it has no peers
    /// to dial and mints `root_key` itself; a non-genesis POST with no usable
    /// bootnode is rejected with `400`.
    pub bootnodes: Vec<String>,
}

/// Per-node settings — values that depend on which node receives the config,
/// unlike `[network]`, whose fields never do.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    /// The node's public IP address. Azure NICs hold private addresses, so
    /// reth's NAT autodetection can't be trusted; tdx-init renders this into
    /// `reth-p2p.env`'s `RETH_NAT_FLAG` as `--nat extip:<ip>` so reth
    /// advertises the correct external address to peers. Also used to drop
    /// this node's own enode when deriving root-key fetch peers from
    /// `[network].bootnodes`. Validated as an `IpAddr` at POST time
    /// (`bin/tdx-init/src/peers.rs`).
    pub external_ip: String,

    /// Root-key custody flag: true iff this node is the network's genesis
    /// node — the one whose custodian generates `root_key` locally with
    /// OsRng. Every other node must leave this `false` (the default) and
    /// fetch from a peer derived from `[network].bootnodes`. Setting it on
    /// multiple nodes causes a silent network split (each generates a
    /// different `root_key`; downstream nodes that fetch from one can't
    /// decrypt state from the other). Rendered to `custodian.env` as
    /// `SEISMIC_CUSTODIAN_GENESIS_NODE`.
    #[serde(default)]
    pub genesis_node: bool,

    /// TLS identity for this node's public RPC; see [`DomainConfig`].
    pub domain: DomainConfig,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_toml_payload() {
        let toml_input = r#"
[network]
manifest_base64 = "eyJtYW5pZmVzdF92ZXJzaW9uIjogMX0K"
reth_genesis_base64 = "eyJjb25maWciOnt9fQ=="
summit_genesis_base64 = "bmFtZXNwYWNlID0gIl9TVU1NSVQiCg=="
bootnodes = ["enode://abc@10.0.0.1:30303", "enode://def@10.0.0.2:30303"]

[node]
external_ip = "203.0.113.7"
genesis_node = true

[node.domain]
name = "node1.example.com"
email = "ops@example.com"
"#;
        let cfg: InitConfig = toml::from_str(toml_input).unwrap();
        assert_eq!(
            cfg.network.manifest_base64,
            "eyJtYW5pZmVzdF92ZXJzaW9uIjogMX0K"
        );
        assert_eq!(cfg.network.bootnodes.len(), 2);
        assert_eq!(cfg.node.external_ip, "203.0.113.7");
        assert!(cfg.node.genesis_node);
        assert_eq!(cfg.node.domain.name, "node1.example.com");
        assert_eq!(cfg.node.domain.email, "ops@example.com");
    }

    #[test]
    fn genesis_node_defaults_to_false() {
        // Fetching from a peer is the safe default: an accidentally-omitted
        // flag must never mint a second root_key.
        let toml_input = r#"
[network]
manifest_base64 = "eyJtYW5pZmVzdF92ZXJzaW9uIjogMX0K"
reth_genesis_base64 = "eyJjb25maWciOnt9fQ=="
summit_genesis_base64 = "bmFtZXNwYWNlID0gIl9TVU1NSVQiCg=="
bootnodes = []

[node]
external_ip = "203.0.113.7"

[node.domain]
name = "node1.example.com"
email = "ops@example.com"
"#;
        let cfg: InitConfig = toml::from_str(toml_input).unwrap();
        assert!(!cfg.node.genesis_node);
    }

    #[test]
    fn accepts_empty_bootnodes() {
        // The genesis node has no peers to dial: the key is required but an
        // empty list parses fine (the genesis-only rule lives in
        // bin/tdx-init/src/peers.rs).
        let toml_input = r#"
[network]
manifest_base64 = "eyJtYW5pZmVzdF92ZXJzaW9uIjogMX0K"
reth_genesis_base64 = "eyJjb25maWciOnt9fQ=="
summit_genesis_base64 = "bmFtZXNwYWNlID0gIl9TVU1NSVQiCg=="
bootnodes = []

[node]
external_ip = "203.0.113.7"
genesis_node = true

[node.domain]
name = "node1.example.com"
email = "ops@example.com"
"#;
        let cfg: InitConfig = toml::from_str(toml_input).unwrap();
        assert!(cfg.network.bootnodes.is_empty());
    }

    #[test]
    fn requires_bootnodes_field() {
        let toml_input = r#"
[network]
manifest_base64 = "eyJtYW5pZmVzdF92ZXJzaW9uIjogMX0K"
reth_genesis_base64 = "eyJjb25maWciOnt9fQ=="
summit_genesis_base64 = "bmFtZXNwYWNlID0gIl9TVU1NSVQiCg=="

[node]
external_ip = "203.0.113.7"

[node.domain]
name = "node1.example.com"
email = "ops@example.com"
"#;
        let err = toml::from_str::<InitConfig>(toml_input).unwrap_err();
        assert!(err.to_string().contains("bootnodes"));
    }

    #[test]
    fn requires_reth_genesis_field() {
        // A config without the genesis must get a clean 400 here, not a node
        // whose reth has no chain spec.
        let toml_input = r#"
[network]
manifest_base64 = "eyJtYW5pZmVzdF92ZXJzaW9uIjogMX0K"
summit_genesis_base64 = "bmFtZXNwYWNlID0gIl9TVU1NSVQiCg=="
bootnodes = []

[node]
external_ip = "203.0.113.7"

[node.domain]
name = "node1.example.com"
email = "ops@example.com"
"#;
        let err = toml::from_str::<InitConfig>(toml_input).unwrap_err();
        assert!(err.to_string().contains("reth_genesis_base64"));
    }

    #[test]
    fn requires_summit_genesis_field() {
        // Same rule as the reth half: without the consensus genesis the POST
        // must 400, not produce a node whose summit blocks forever waiting
        // for a genesis file that never arrives.
        let toml_input = r#"
[network]
manifest_base64 = "eyJtYW5pZmVzdF92ZXJzaW9uIjogMX0K"
reth_genesis_base64 = "eyJjb25maWciOnt9fQ=="
bootnodes = []

[node]
external_ip = "203.0.113.7"

[node.domain]
name = "node1.example.com"
email = "ops@example.com"
"#;
        let err = toml::from_str::<InitConfig>(toml_input).unwrap_err();
        assert!(err.to_string().contains("summit_genesis_base64"));
    }

    #[test]
    fn requires_network_section() {
        let toml_input = r#"
[node]
external_ip = "203.0.113.7"
genesis_node = true

[node.domain]
name = "node1.example.com"
email = "ops@example.com"
"#;
        let err = toml::from_str::<InitConfig>(toml_input).unwrap_err();
        assert!(err.to_string().contains("network"));
    }

    #[test]
    fn requires_node_section() {
        let toml_input = r#"
[network]
manifest_base64 = "eyJtYW5pZmVzdF92ZXJzaW9uIjogMX0K"
reth_genesis_base64 = "eyJjb25maWciOnt9fQ=="
summit_genesis_base64 = "bmFtZXNwYWNlID0gIl9TVU1NSVQiCg=="
bootnodes = []
"#;
        let err = toml::from_str::<InitConfig>(toml_input).unwrap_err();
        assert!(err.to_string().contains("node"));
    }

    #[test]
    fn requires_external_ip_field() {
        let toml_input = r#"
[network]
manifest_base64 = "eyJtYW5pZmVzdF92ZXJzaW9uIjogMX0K"
reth_genesis_base64 = "eyJjb25maWciOnt9fQ=="
summit_genesis_base64 = "bmFtZXNwYWNlID0gIl9TVU1NSVQiCg=="
bootnodes = []

[node]
[node.domain]
name = "node1.example.com"
email = "ops@example.com"
"#;
        let err = toml::from_str::<InitConfig>(toml_input).unwrap_err();
        assert!(err.to_string().contains("external_ip"));
    }

    #[test]
    fn requires_domain_in_node_section() {
        let toml_input = r#"
[network]
manifest_base64 = "eyJtYW5pZmVzdF92ZXJzaW9uIjogMX0K"
reth_genesis_base64 = "eyJjb25maWciOnt9fQ=="
summit_genesis_base64 = "bmFtZXNwYWNlID0gIl9TVU1NSVQiCg=="
bootnodes = []

[node]
external_ip = "203.0.113.7"
"#;
        let err = toml::from_str::<InitConfig>(toml_input).unwrap_err();
        assert!(err.to_string().contains("domain"));
    }

    #[test]
    fn rejects_unknown_field_in_network_section() {
        let toml_input = r#"
[network]
manifest_base64 = "eyJ9"
reth_genesis_base64 = "eyJjb25maWciOnt9fQ=="
summit_genesis_base64 = "bmFtZXNwYWNlID0gIl9TVU1NSVQiCg=="
bootnodes = []
network_id = "0xabcd"

[node]
external_ip = "203.0.113.7"

[node.domain]
name = "node1.example.com"
email = "ops@example.com"
"#;
        let err = toml::from_str::<InitConfig>(toml_input).unwrap_err();
        assert!(err.to_string().to_lowercase().contains("unknown"));
    }

    #[test]
    fn rejects_unknown_field_in_node_section() {
        let toml_input = r#"
[network]
manifest_base64 = "eyJ9"
reth_genesis_base64 = "eyJjb25maWciOnt9fQ=="
summit_genesis_base64 = "bmFtZXNwYWNlID0gIl9TVU1NSVQiCg=="
bootnodes = []

[node]
external_ip = "203.0.113.7"
internal_ip = "10.0.0.1"

[node.domain]
name = "node1.example.com"
email = "ops@example.com"
"#;
        let err = toml::from_str::<InitConfig>(toml_input).unwrap_err();
        assert!(err.to_string().to_lowercase().contains("unknown"));
    }

    #[test]
    fn rejects_removed_root_key_section() {
        // The old wire schema's [root_key] section (genesis_node + peers)
        // folded into [node] / derivation: an old deploy CLI must get a clean
        // 400, not a node silently running with defaults.
        let toml_input = r#"
[root_key]
genesis_node = true

[network]
manifest_base64 = "eyJ9"
reth_genesis_base64 = "eyJjb25maWciOnt9fQ=="
summit_genesis_base64 = "bmFtZXNwYWNlID0gIl9TVU1NSVQiCg=="
bootnodes = []

[node]
external_ip = "203.0.113.7"

[node.domain]
name = "node1.example.com"
email = "ops@example.com"
"#;
        let err = toml::from_str::<InitConfig>(toml_input).unwrap_err();
        assert!(err.to_string().to_lowercase().contains("unknown"));
    }

    #[test]
    fn rejects_unknown_top_level_section() {
        let toml_input = r#"
[network]
manifest_base64 = "eyJ9"
reth_genesis_base64 = "eyJjb25maWciOnt9fQ=="
summit_genesis_base64 = "bmFtZXNwYWNlID0gIl9TVU1NSVQiCg=="
bootnodes = []

[node]
external_ip = "203.0.113.7"

[node.domain]
name = "node1.example.com"
email = "ops@example.com"

[bogus]
field = "value"
"#;
        let err = toml::from_str::<InitConfig>(toml_input).unwrap_err();
        assert!(err.to_string().to_lowercase().contains("unknown"));
    }
}
