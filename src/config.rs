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
    /// of these peers via the `boot_share_root_key` RPC. Required for
    /// non-genesis nodes; the enclave fails fast at startup if this
    /// list is empty and `genesis_node` is false.
    #[serde(default)]
    pub peers: Vec<String>,
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
"#;
        let cfg: InitConfig = toml::from_str(toml_input).unwrap();
        assert_eq!(cfg.domain.name, "node1.example.com");
        assert_eq!(cfg.domain.email, "ops@example.com");
        assert!(cfg.enclave.genesis_node);
        assert_eq!(cfg.enclave.peers.len(), 2);
    }

    #[test]
    fn enclave_section_is_optional_with_defaults() {
        let toml_input = r#"
[domain]
name = "node1.example.com"
email = "ops@example.com"
"#;
        let cfg: InitConfig = toml::from_str(toml_input).unwrap();
        assert!(!cfg.enclave.genesis_node);
        assert!(cfg.enclave.peers.is_empty());
    }

    #[test]
    fn rejects_unknown_top_level_section() {
        let toml_input = r#"
[domain]
name = "node1.example.com"
email = "ops@example.com"

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
"#;
        let err = toml::from_str::<InitConfig>(toml_input).unwrap_err();
        assert!(err.to_string().to_lowercase().contains("unknown"));
    }

    #[test]
    fn requires_domain_section() {
        let toml_input = r#"
[enclave]
genesis_node = true
"#;
        let err = toml::from_str::<InitConfig>(toml_input).unwrap_err();
        assert!(err.to_string().contains("domain"));
    }
}
