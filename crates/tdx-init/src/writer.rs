use crate::config::InitConfig;
use crate::error::Result;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tokio::fs;
use tracing::info;

// TODO: ownership and permissions on these files should be a seismic-images
// concern (User= + ExecStartPre/Post in tdx-init.service or tmpfiles.d), not
// baked into the binary. Today tdx-init runs as root and we explicitly
// chmod 0o644; the cleaner shape is to run tdx-init as a tdx-init:eth
// system user, let the default umask produce 0o644, and stop setting mode
// here. Each per-component file's group/other bits should be tightened in
// seismic-images so only the relevant service user can read it.
pub const DEFAULT_FILE_MODE: u32 = 0o644;

/// Translate the operator-supplied [`InitConfig`] into per-service config
/// files under `conf_dir`. Each downstream service reads its own file in
/// its native format (env-var pairs for clap-based and bash consumers);
/// tdx-init is the schema translator.
pub async fn write_service_configs(conf_dir: &Path, config: &InitConfig) -> Result<()> {
    fs::create_dir_all(conf_dir).await?;
    write_domain_env(conf_dir, config).await?;
    write_enclave_env(conf_dir, config).await?;
    if let Some(network) = &config.network {
        write_network_manifest(conf_dir, network).await?;
    }
    Ok(())
}

/// Write the decoded manifest bytes verbatim (byte-exactness rule):
/// consumers derive `network_id` by hashing this file themselves, so any
/// re-rendering here would silently change the network's identity.
async fn write_network_manifest(
    conf_dir: &Path,
    network: &crate::config::NetworkConfig,
) -> Result<()> {
    let path = conf_dir.join("network-manifest.json");
    let bytes = crate::manifest::decode_and_validate(&network.manifest_base64)?;
    write_with_mode(&path, &bytes, DEFAULT_FILE_MODE).await?;
    info!(
        "wrote {} (network_id {})",
        path.display(),
        crate::manifest::network_id_hex(&bytes),
    );
    Ok(())
}

async fn write_domain_env(conf_dir: &Path, config: &InitConfig) -> Result<()> {
    let path = conf_dir.join("domain.env");
    let content = format!(
        "DOMAIN_NAME={}\nDOMAIN_EMAIL={}\n",
        config.domain.name, config.domain.email,
    );
    write_with_mode(&path, &content, DEFAULT_FILE_MODE).await?;
    info!("wrote {}", path.display());
    Ok(())
}

async fn write_enclave_env(conf_dir: &Path, config: &InitConfig) -> Result<()> {
    let path = conf_dir.join("enclave.env");
    let content = format!(
        "SEISMIC_ENCLAVE_GENESIS_NODE={}\nSEISMIC_ENCLAVE_PEERS={}\n",
        config.enclave.genesis_node,
        config.enclave.peers.join(","),
    );
    write_with_mode(&path, &content, DEFAULT_FILE_MODE).await?;
    info!("wrote {}", path.display());
    Ok(())
}

async fn write_with_mode(path: &Path, content: impl AsRef<[u8]>, mode: u32) -> Result<()> {
    fs::write(path, content).await?;
    let mut perms = fs::metadata(path).await?.permissions();
    perms.set_mode(mode);
    fs::set_permissions(path, perms).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DomainConfig, EnclaveConfig};
    use tempfile::TempDir;

    fn sample_config(genesis_node: bool, peers: Vec<&str>) -> InitConfig {
        InitConfig {
            domain: DomainConfig {
                email: "ops@example.com".to_string(),
                name: "node1.example.com".to_string(),
            },
            enclave: EnclaveConfig {
                genesis_node,
                peers: peers.into_iter().map(String::from).collect(),
            },
            network: None,
        }
    }

    #[tokio::test]
    async fn writes_both_files_with_expected_contents() {
        let tmp = TempDir::new().unwrap();
        let cfg = sample_config(true, vec!["http://10.0.0.1:7878", "http://10.0.0.2:7878"]);

        write_service_configs(tmp.path(), &cfg).await.unwrap();

        let domain = std::fs::read_to_string(tmp.path().join("domain.env")).unwrap();
        assert_eq!(
            domain,
            "DOMAIN_NAME=node1.example.com\nDOMAIN_EMAIL=ops@example.com\n"
        );

        let enclave = std::fs::read_to_string(tmp.path().join("enclave.env")).unwrap();
        assert_eq!(
            enclave,
            "SEISMIC_ENCLAVE_GENESIS_NODE=true\n\
             SEISMIC_ENCLAVE_PEERS=http://10.0.0.1:7878,http://10.0.0.2:7878\n"
        );
    }

    #[tokio::test]
    async fn handles_empty_peers() {
        let tmp = TempDir::new().unwrap();
        let cfg = sample_config(false, vec![]);

        write_service_configs(tmp.path(), &cfg).await.unwrap();

        let enclave = std::fs::read_to_string(tmp.path().join("enclave.env")).unwrap();
        assert_eq!(
            enclave,
            "SEISMIC_ENCLAVE_GENESIS_NODE=false\nSEISMIC_ENCLAVE_PEERS=\n"
        );
    }

    #[tokio::test]
    async fn writes_network_manifest_verbatim() {
        use base64::Engine as _;

        let tmp = TempDir::new().unwrap();
        let mut cfg = sample_config(false, vec![]);
        // A valid manifest with a non-canonical byte (trailing newline): the
        // written file must be the decoded bytes exactly, not a re-rendering.
        let raw = [
            include_bytes!("../fixtures/network-manifest-v1.json").as_slice(),
            b"\n",
        ]
        .concat();
        cfg.network = Some(crate::config::NetworkConfig {
            manifest_base64: base64::engine::general_purpose::STANDARD.encode(&raw),
        });

        write_service_configs(tmp.path(), &cfg).await.unwrap();

        let written = std::fs::read(tmp.path().join("network-manifest.json")).unwrap();
        assert_eq!(written, raw);
    }

    #[tokio::test]
    async fn skips_network_manifest_when_section_absent() {
        let tmp = TempDir::new().unwrap();
        let cfg = sample_config(false, vec![]);

        write_service_configs(tmp.path(), &cfg).await.unwrap();

        assert!(!tmp.path().join("network-manifest.json").exists());
    }

    #[tokio::test]
    async fn sets_default_mode() {
        let tmp = TempDir::new().unwrap();
        let cfg = sample_config(false, vec![]);

        write_service_configs(tmp.path(), &cfg).await.unwrap();

        for name in ["domain.env", "enclave.env"] {
            let meta = std::fs::metadata(tmp.path().join(name)).unwrap();
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(mode, DEFAULT_FILE_MODE);
        }
    }
}
