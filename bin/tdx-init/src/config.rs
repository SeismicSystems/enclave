use serde::{Deserialize, Serialize};

/// Operator-supplied initialization config, received over HTTP at deploy
/// time and fanned out by tdx-init into per-component config files under
/// [`crate::CONF_DIR`].
///
/// Two sections, split by provenance: `[network]` is coordinator-produced —
/// a function of the network at POST time, never tailored to the recipient —
/// while `[node]` is this node only. Network-indexed is weaker than
/// cohort-identical: the bootnode set evolves as the network does (empty at
/// greenfield stage 1), so nodes configured at different times hold
/// different snapshots; only the manifest and reth genesis must truly match
/// across the cohort — differing bytes there mean a different network.
/// Anything derivable from these is derived rather than delivered twice —
/// e.g. the root-key fetch peers come from `[network].bootnodes`
/// (`src/peers.rs`), so there is no second list that could skew from it.
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
/// node's public RPC. Written by the writer module to `domain.env` under
/// [`crate::CONF_DIR`] as `DOMAIN_NAME=...` / `DOMAIN_EMAIL=...`, which
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
/// to `network-manifest.json` under [`crate::CONF_DIR`], never
/// parse-and-re-serialize. Validation lives in `src/manifest.rs` (schema in
/// the `seismic-network-manifest` crate).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    /// base64 (standard alphabet) of the network-manifest.json bytes, as
    /// emitted by the deploy tool's manifest assembly step.
    pub manifest_base64: String,

    /// base64 encoding of the reth genesis JSON — the chain spec
    /// every node's reth boots from (`--chain
    /// /run/seismic/conf/reth-genesis.json`). Network-wide like the manifest,
    /// whose `eth.genesis_hash` pins its genesis block; required because a
    /// node booted without it has no chain spec and reth crash-loops.
    /// Validated at POST time against the manifest's `eth.chain_id`
    /// (`src/reth_genesis.rs`) and written verbatim to `reth-genesis.json`
    /// under [`crate::CONF_DIR`].
    pub reth_genesis_base64: String,

    /// Network-wide devp2p bootnodes, as `enode://<128 hex pubkey>@host:port`
    /// URLs — the single source for the cohort's peer machines. Feeds reth
    /// verbatim (`reth-p2p.env`'s `RETH_BOOTNODES_FLAG`) and, derived, the
    /// attestation service's root-key fetch list (`attestation.env`:
    /// `http://<host>:7878` per bootnode, this node's own entry dropped);
    /// validation and derivation live in `src/peers.rs`. The field is required,
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
    /// (`src/peers.rs`).
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
        // empty list parses fine (the genesis-only rule lives in src/peers.rs).
        let toml_input = r#"
[network]
manifest_base64 = "eyJtYW5pZmVzdF92ZXJzaW9uIjogMX0K"
reth_genesis_base64 = "eyJjb25maWciOnt9fQ=="
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
