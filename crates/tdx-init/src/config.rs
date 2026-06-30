use serde::{Deserialize, Serialize};

/// Operator-supplied initialization config, received over HTTP at deploy
/// time and fanned out by tdx-init into per-component env files under
/// [`crate::CONF_DIR`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitConfig {
    pub domain: DomainConfig,
    #[serde(default)]
    pub enclave: EnclaveConfig,
    /// Required: enclave-server reads `network-manifest.json` at startup to
    /// derive `network_id` and bind every attestation to it, and is fatal
    /// without it. A POST that omits `[network]` therefore 400s here rather
    /// than booting a node that crash-loops on the missing file. The deploy
    /// CLI merges the network-wide manifest into the per-node config at POST time.
    pub network: NetworkConfig,
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

/// Bootstrap config for the enclave server. Fields get converted to env vars,
/// and written to `enclave.env` under [`crate::CONF_DIR`] which
/// `enclave.service` (in seismic-images) loads via `EnvironmentFile=`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnclaveConfig {
    /// True iff this node is the network's genesis enclave — the one that
    /// generates `root_key` locally with OsRng. Every other node must
    /// leave this `false` (the default) and fetch from peers. Setting
    /// it on multiple nodes causes a silent network split (each generates
    /// a different `root_key`; downstream nodes that fetch from one
    /// can't decrypt state from the other).
    #[serde(default)]
    pub genesis_node: bool,

    /// Peer enclave URLs (e.g. `http://10.0.0.1:7878`). When
    /// `genesis_node` is false, the enclave fetches `root_key` from one
    /// of these peers via the `getWrappedRootKey` RPC. Required for
    /// non-genesis nodes; the enclave fails fast at startup if this
    /// list is empty and `genesis_node` is false.
    #[serde(default)]
    pub peers: Vec<String>,
}

/// The network's identity document, common to genesis and joining nodes.
///
/// `network_id = SHA-256(exact network-manifest.json bytes)`, so the manifest
/// travels base64-encoded (opaque bytes) rather than as an inline string:
/// tdx-init validates it at POST time and writes the decoded bytes verbatim
/// to `network-manifest.json` under [`crate::CONF_DIR`], never
/// parse-and-re-serialize. Validation rules live in `src/manifest.rs`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    /// base64 (standard alphabet) of the network-manifest.json bytes, as
    /// emitted by the deploy tool's manifest assembly step.
    pub manifest_base64: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_toml_payload() {
        let toml_input = r#"
[domain]
name = "node1.example.com"
email = "ops@example.com"

[enclave]
genesis_node = true
peers = ["http://10.0.0.1:7878", "http://10.0.0.2:7878"]

[network]
manifest_base64 = "eyJtYW5pZmVzdF92ZXJzaW9uIjogMX0K"
"#;
        let cfg: InitConfig = toml::from_str(toml_input).unwrap();
        assert_eq!(cfg.domain.name, "node1.example.com");
        assert_eq!(cfg.domain.email, "ops@example.com");
        assert!(cfg.enclave.genesis_node);
        assert_eq!(cfg.enclave.peers.len(), 2);
        assert_eq!(
            cfg.network.manifest_base64,
            "eyJtYW5pZmVzdF92ZXJzaW9uIjogMX0K"
        );
    }

    #[test]
    fn parses_network_section() {
        let toml_input = r#"
[domain]
name = "node1.example.com"
email = "ops@example.com"

[network]
manifest_base64 = "eyJtYW5pZmVzdF92ZXJzaW9uIjogMX0K"
"#;
        let cfg: InitConfig = toml::from_str(toml_input).unwrap();
        assert_eq!(
            cfg.network.manifest_base64,
            "eyJtYW5pZmVzdF92ZXJzaW9uIjogMX0K"
        );
    }

    #[test]
    fn rejects_unknown_field_in_network_section() {
        let toml_input = r#"
[domain]
name = "node1.example.com"
email = "ops@example.com"

[network]
manifest_base64 = "eyJ9"
network_id = "0xabcd"
"#;
        let err = toml::from_str::<InitConfig>(toml_input).unwrap_err();
        assert!(err.to_string().to_lowercase().contains("unknown"));
    }

    #[test]
    fn enclave_section_is_optional_with_defaults() {
        let toml_input = r#"
[domain]
name = "node1.example.com"
email = "ops@example.com"

[network]
manifest_base64 = "eyJtYW5pZmVzdF92ZXJzaW9uIjogMX0K"
"#;
        let cfg: InitConfig = toml::from_str(toml_input).unwrap();
        assert!(!cfg.enclave.genesis_node);
        assert!(cfg.enclave.peers.is_empty());
    }

    #[test]
    fn requires_network_section() {
        let toml_input = r#"
[domain]
name = "node1.example.com"
email = "ops@example.com"

[enclave]
genesis_node = true
"#;
        let err = toml::from_str::<InitConfig>(toml_input).unwrap_err();
        assert!(err.to_string().contains("network"));
    }

    #[test]
    fn rejects_unknown_top_level_section() {
        let toml_input = r#"
[domain]
name = "node1.example.com"
email = "ops@example.com"

[network]
manifest_base64 = "eyJ9"

[bogus]
field = "value"
"#;
        let err = toml::from_str::<InitConfig>(toml_input).unwrap_err();
        assert!(err.to_string().to_lowercase().contains("unknown"));
    }

    #[test]
    fn rejects_unknown_field_in_enclave_section() {
        let toml_input = r#"
[domain]
name = "node1.example.com"
email = "ops@example.com"

[enclave]
genesis_node = false
log_level = "trace"

[network]
manifest_base64 = "eyJ9"
"#;
        let err = toml::from_str::<InitConfig>(toml_input).unwrap_err();
        assert!(err.to_string().to_lowercase().contains("unknown"));
    }

    #[test]
    fn requires_domain_section() {
        let toml_input = r#"
[enclave]
genesis_node = true

[network]
manifest_base64 = "eyJ9"
"#;
        let err = toml::from_str::<InitConfig>(toml_input).unwrap_err();
        assert!(err.to_string().contains("domain"));
    }
}
