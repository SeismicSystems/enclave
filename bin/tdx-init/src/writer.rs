use crate::error::Result;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tdx_init_config::{Bootnode, DomainConfig, InitConfig};
use tokio::fs;
use tracing::info;

pub const DEFAULT_FILE_MODE: u32 = 0o644;

/// Translate the operator-supplied [`InitConfig`] into per-service config
/// files under `conf_dir`. Each downstream service reads its own file in
/// its native format (env-var pairs for clap-based and bash consumers);
/// tdx-init is the schema translator.
///
/// Every input is validated before the first byte is written, so a bad config
/// leaves no `conf_dir` and no partially populated set of files behind. The
/// second half is then pure filesystem work that can only fail on I/O.
///
/// `candidate_tx_io_pk_path` is the custodian's candidate tx_io_pk file,
/// compared with the manifest's pin to decide whether this node may go without
/// peers.
pub async fn write_service_configs(
    conf_dir: &Path,
    candidate_tx_io_pk_path: &Path,
    config: &InitConfig,
) -> Result<()> {
    let manifest = crate::manifest::decode_and_validate(&config.network.manifest_base64)?;
    let peers = crate::peers::derive_peer_lists(
        &config.node,
        &config.network.bootnodes,
        crate::peers::holds_pinned_candidate(candidate_tx_io_pk_path, &manifest.founding_tx_io_pk)?,
    )?;
    let summit_addr = crate::peers::summit_advertised_addr(&config.node);
    let genesis = crate::reth_genesis::decode_and_validate(
        &config.network.reth_genesis_base64,
        manifest.chain_id,
    )?;
    let summit_genesis = crate::summit_genesis::decode_and_validate(
        &config.network.summit_genesis_base64,
        &manifest.namespace,
    )?;

    fs::create_dir_all(conf_dir).await?;
    write_domain_env(conf_dir, &config.node.domain).await?;
    write_attestation_svc_env(conf_dir, &peers.root_key_urls).await?;
    write_reth_p2p_env(conf_dir, &peers.peer_enodes, config.node.external_ip).await?;
    write_summit_env(conf_dir, summit_addr).await?;
    write_network_manifest(conf_dir, &manifest).await?;
    write_reth_genesis(conf_dir, &genesis).await?;
    write_summit_genesis(conf_dir, &summit_genesis).await?;
    Ok(())
}

/// Write the validated manifest bytes verbatim (byte-exactness rule):
/// consumers derive `network_id` by hashing this file themselves, so any
/// re-rendering here would silently change the network's identity.
async fn write_network_manifest(
    conf_dir: &Path,
    manifest: &crate::manifest::ValidatedManifest,
) -> Result<()> {
    let path = conf_dir.join("network-manifest.json");
    write_with_mode(&path, &manifest.bytes, DEFAULT_FILE_MODE).await?;
    info!(
        "wrote {} (network_id {})",
        path.display(),
        crate::manifest::network_id_hex(&manifest.bytes),
    );
    Ok(())
}

/// Write the validated reth genesis bytes verbatim: reth parses the file
/// itself (`--chain`), so tdx-init never re-renders it.
async fn write_reth_genesis(conf_dir: &Path, genesis_bytes: &[u8]) -> Result<()> {
    let path = conf_dir.join("reth-genesis.json");
    write_with_mode(&path, genesis_bytes, DEFAULT_FILE_MODE).await?;
    info!("wrote {}", path.display());
    Ok(())
}

/// Write the validated summit genesis bytes verbatim: summit parses the file
/// itself (`--genesis-path`), so tdx-init never re-renders it.
async fn write_summit_genesis(conf_dir: &Path, genesis_bytes: &[u8]) -> Result<()> {
    let path = conf_dir.join("summit-genesis.toml");
    write_with_mode(&path, genesis_bytes, DEFAULT_FILE_MODE).await?;
    info!("wrote {}", path.display());
    Ok(())
}

/// Both values are written unquoted, which is safe only because
/// [`DomainConfig`]'s types admit no whitespace, quote, `$`, backslash or
/// newline.
async fn write_domain_env(conf_dir: &Path, domain: &DomainConfig) -> Result<()> {
    let path = conf_dir.join("domain.env");
    let content = format!(
        "DOMAIN_NAME={}\nDOMAIN_EMAIL={}\n",
        domain.name, domain.email,
    );
    write_with_mode(&path, &content, DEFAULT_FILE_MODE).await?;
    info!("wrote {}", path.display());
    Ok(())
}

/// The attestation service reads this in-process once the sentinel appears:
/// `SEISMIC_ROOT_KEY_PEERS` is where to fetch the root key when the manifest
/// does not pin the local custodian's candidate. The peer list
/// is not a config field: it is derived from `[network].bootnodes` in
/// `crate::peers`.
async fn write_attestation_svc_env(conf_dir: &Path, root_key_peers: &[String]) -> Result<()> {
    let path = conf_dir.join("attestation.env");
    let content = format!("SEISMIC_ROOT_KEY_PEERS={}\n", root_key_peers.join(","));
    write_with_mode(&path, &content, DEFAULT_FILE_MODE).await?;
    info!("wrote {}", path.display());
    Ok(())
}

/// reth's systemd unit loads this via `EnvironmentFile=` and puts the
/// *unquoted* `$RETH_BOOTNODES_FLAG $RETH_TRUSTED_PEERS_FLAG $RETH_NAT_FLAG`
/// on reth's command line. Each var holds a whole flag: systemd word-splits an
/// unquoted expansion, so a populated var expands to argv entries while an
/// empty one drops out entirely. Emitting the flag name inside the var (rather
/// than a bare value) is what lets an empty bootnode list
/// vanish instead of passing `--bootnodes ""`, which reth rejects.
/// `RETH_NAT_FLAG` is always populated (external_ip is required); the two peer
/// flags are empty together, on a node whose cohort names no other machine.
/// Values may contain a space; systemd EnvironmentFile keeps everything after
/// `=` verbatim (no quoting needed), matching the other env files here.
///
/// One enode list fills both peer flags — see `crate::peers::PeerLists` for
/// why reth gets it twice, and for the POST-time validation behind it.
async fn write_reth_p2p_env(
    conf_dir: &Path,
    peer_enodes: &[Bootnode],
    external_ip: IpAddr,
) -> Result<()> {
    let path = conf_dir.join("reth-p2p.env");
    let (bootnodes_flag, trusted_peers_flag) = if peer_enodes.is_empty() {
        (String::new(), String::new())
    } else {
        let csv = peer_enodes
            .iter()
            .map(Bootnode::as_ref)
            .collect::<Vec<_>>()
            .join(",");
        (
            format!("--bootnodes {csv}"),
            format!("--trusted-peers {csv}"),
        )
    };
    let nat_flag = format!("--nat extip:{external_ip}");
    let content = format!(
        "RETH_BOOTNODES_FLAG={bootnodes_flag}\n\
         RETH_TRUSTED_PEERS_FLAG={trusted_peers_flag}\n\
         RETH_NAT_FLAG={nat_flag}\n"
    );
    write_with_mode(&path, &content, DEFAULT_FILE_MODE).await?;
    info!("wrote {}", path.display());
    Ok(())
}

/// summit's systemd unit loads this via `EnvironmentFile=` and splices
/// `SUMMIT_ADVERTISED_ADDR` into `--ip`, as a quoted expansion: it is always
/// populated (external_ip is required), so it needs none of the empty-var
/// disappearing act `reth-p2p.env` above depends on.
///
/// A complete `<ip>:<port>` rather than a host the unit appends a port to —
/// summit parses the value as one socket address, and IPv6 makes composing it
/// textually a bracketing trap. See `crate::peers::summit_advertised_addr` for
/// what the address means to the cohort.
async fn write_summit_env(conf_dir: &Path, advertised_addr: SocketAddr) -> Result<()> {
    let path = conf_dir.join("summit.env");
    let content = format!("SUMMIT_ADVERTISED_ADDR={advertised_addr}\n");
    write_with_mode(&path, &content, DEFAULT_FILE_MODE).await?;
    info!("wrote {} (advertising {advertised_addr})", path.display());
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
    use base64::Engine as _;
    use tdx_init_config::{NetworkConfig, NodeConfig};
    use tempfile::TempDir;

    /// A candidate tx_io_pk file naming the fixture manifest's pin, so
    /// `sample_config` (no bootnodes) is valid; the guard keeps the file alive.
    fn pinned_candidate() -> (TempDir, std::path::PathBuf) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("candidate-tx-io-pk");
        let manifest =
            crate::manifest::decode_and_validate(&sample_config().network.manifest_base64).unwrap();
        seismic_custodian_ipc::candidate_tx_io_pk::write(&path, &manifest.founding_tx_io_pk)
            .unwrap();
        (dir, path)
    }

    /// A valid enode at `host_port` (128-hex pubkey).
    fn enode(host_port: &str) -> Bootnode {
        format!("enode://{}@{host_port}", "a".repeat(128))
            .parse()
            .unwrap()
    }

    fn sample_config() -> InitConfig {
        InitConfig {
            network: NetworkConfig {
                manifest_base64: base64::engine::general_purpose::STANDARD.encode(include_bytes!(
                    "../../../crates/network-manifest/fixtures/network-manifest-v1.json"
                )),
                // A genesis whose chainId matches the fixture manifest's.
                reth_genesis_base64: base64::engine::general_purpose::STANDARD.encode(
                    crate::reth_genesis::tests::genesis_json(
                        crate::reth_genesis::tests::FIXTURE_CHAIN_ID,
                    ),
                ),
                // A summit genesis whose namespace matches the fixture manifest's.
                summit_genesis_base64: base64::engine::general_purpose::STANDARD.encode(
                    crate::summit_genesis::tests::genesis_toml(
                        crate::summit_genesis::tests::FIXTURE_NAMESPACE,
                    ),
                ),
                bootnodes: vec![],
            },
            node: NodeConfig {
                external_ip: "203.0.113.1".parse().unwrap(),
                domain: DomainConfig {
                    email: "ops@example.com".parse().unwrap(),
                    name: "node1.example.com".parse().unwrap(),
                },
            },
        }
    }

    #[tokio::test]
    async fn writes_env_files_with_expected_contents() {
        let tmp = TempDir::new().unwrap();
        let mut cfg = sample_config();
        cfg.network.bootnodes = vec![enode("10.0.0.1:30303"), enode("10.0.0.2:30303")];

        let (_candidate_dir, candidate) = pinned_candidate();
        write_service_configs(tmp.path(), &candidate, &cfg)
            .await
            .unwrap();

        let domain = std::fs::read_to_string(tmp.path().join("domain.env")).unwrap();
        assert_eq!(
            domain,
            "DOMAIN_NAME=node1.example.com\nDOMAIN_EMAIL=ops@example.com\n"
        );

        // The peer list is derived from the bootnode hosts, not delivered.
        let attestation = std::fs::read_to_string(tmp.path().join("attestation.env")).unwrap();
        assert_eq!(
            attestation,
            "SEISMIC_ROOT_KEY_PEERS=http://10.0.0.1:7878,http://10.0.0.2:7878\n"
        );
    }

    #[tokio::test]
    async fn no_bootnodes_gets_empty_peers() {
        let tmp = TempDir::new().unwrap();
        let cfg = sample_config();

        let (_candidate_dir, candidate) = pinned_candidate();
        write_service_configs(tmp.path(), &candidate, &cfg)
            .await
            .unwrap();

        let attestation = std::fs::read_to_string(tmp.path().join("attestation.env")).unwrap();
        assert_eq!(attestation, "SEISMIC_ROOT_KEY_PEERS=\n");
    }

    #[tokio::test]
    async fn drops_own_enode_from_every_rendered_list() {
        // The persisted founding bootnode set includes this node's own enode.
        // Nothing this node uses to reach others should name itself, so it is
        // absent from both reth flags and from the root-key fetch list.
        let tmp = TempDir::new().unwrap();
        let mut cfg = sample_config();
        cfg.network.bootnodes = vec![enode("203.0.113.1:30303"), enode("10.0.0.2:30303")];

        let (_candidate_dir, candidate) = pinned_candidate();
        write_service_configs(tmp.path(), &candidate, &cfg)
            .await
            .unwrap();

        let attestation = std::fs::read_to_string(tmp.path().join("attestation.env")).unwrap();
        assert_eq!(attestation, "SEISMIC_ROOT_KEY_PEERS=http://10.0.0.2:7878\n");

        let p2p = std::fs::read_to_string(tmp.path().join("reth-p2p.env")).unwrap();
        assert!(!p2p.contains("203.0.113.1:30303"), "{p2p}");
        let id = "a".repeat(128);
        assert_eq!(
            p2p,
            format!(
                "RETH_BOOTNODES_FLAG=--bootnodes enode://{id}@10.0.0.2:30303\nRETH_TRUSTED_PEERS_FLAG=--trusted-peers enode://{id}@10.0.0.2:30303\nRETH_NAT_FLAG=--nat extip:203.0.113.1\n"
            )
        );
    }

    #[tokio::test]
    async fn a_rejected_config_writes_nothing() {
        // Validation runs to completion before any file is written, so a
        // failure in the last-validated artifact still leaves an empty conf
        // dir rather than a set of files the boot chain would go on to read.
        let tmp = TempDir::new().unwrap();
        let mut cfg = sample_config();
        cfg.network.summit_genesis_base64 = "not base64".to_string();

        let (_candidate_dir, candidate) = pinned_candidate();
        let err = write_service_configs(tmp.path(), &candidate, &cfg)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            crate::error::TdxInitError::InvalidSummitGenesis(_)
        ));
        assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn an_unpinned_node_without_peers_writes_nothing() {
        let tmp = TempDir::new().unwrap();
        let no_candidate_tx_io_pk = tmp.path().join("no-candidate-tx-io-pk");

        let err = write_service_configs(tmp.path(), &no_candidate_tx_io_pk, &sample_config())
            .await
            .unwrap_err();
        assert!(matches!(err, crate::error::TdxInitError::InvalidPeers(_)));
        assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn writes_reth_p2p_env_populated() {
        let tmp = TempDir::new().unwrap();
        let mut cfg = sample_config();
        cfg.network.bootnodes = vec![enode("10.0.0.1:30303"), enode("10.0.0.2:30303")];
        cfg.node.external_ip = "203.0.113.7".parse().unwrap();

        let (_candidate_dir, candidate) = pinned_candidate();
        write_service_configs(tmp.path(), &candidate, &cfg)
            .await
            .unwrap();

        let p2p = std::fs::read_to_string(tmp.path().join("reth-p2p.env")).unwrap();
        let id = "a".repeat(128);
        assert_eq!(
            p2p,
            format!(
                "RETH_BOOTNODES_FLAG=--bootnodes enode://{id}@10.0.0.1:30303,enode://{id}@10.0.0.2:30303\nRETH_TRUSTED_PEERS_FLAG=--trusted-peers enode://{id}@10.0.0.1:30303,enode://{id}@10.0.0.2:30303\nRETH_NAT_FLAG=--nat extip:203.0.113.7\n"
            )
        );
    }

    #[tokio::test]
    async fn writes_reth_p2p_env_without_bootnodes() {
        // A box founding alone has no bootnodes: RETH_BOOTNODES_FLAG and
        // RETH_TRUSTED_PEERS_FLAG are empty so reth.service's unquoted
        // expansion drops them, while RETH_NAT_FLAG is still populated from the
        // (required) external_ip.
        let tmp = TempDir::new().unwrap();
        let cfg = sample_config();

        let (_candidate_dir, candidate) = pinned_candidate();
        write_service_configs(tmp.path(), &candidate, &cfg)
            .await
            .unwrap();

        let p2p = std::fs::read_to_string(tmp.path().join("reth-p2p.env")).unwrap();
        assert_eq!(
            p2p,
            "RETH_BOOTNODES_FLAG=\nRETH_TRUSTED_PEERS_FLAG=\nRETH_NAT_FLAG=--nat extip:203.0.113.1\n"
        );
    }

    #[tokio::test]
    async fn writes_summit_env() {
        let tmp = TempDir::new().unwrap();
        let mut cfg = sample_config();
        cfg.network.bootnodes = vec![enode("10.0.0.2:30303")];
        cfg.node.external_ip = "203.0.113.7".parse().unwrap();

        let (_candidate_dir, candidate) = pinned_candidate();
        write_service_configs(tmp.path(), &candidate, &cfg)
            .await
            .unwrap();

        let env = std::fs::read_to_string(tmp.path().join("summit.env")).unwrap();
        assert_eq!(env, "SUMMIT_ADVERTISED_ADDR=203.0.113.7:18551\n");
    }

    #[tokio::test]
    async fn writes_summit_env_bracketing_ipv6() {
        // summit parses the value as a SocketAddr, which requires the brackets
        // an IPv6 external_ip does not carry. Appending ":<port>" to the bare
        // address would emit a value it rejects, so the address is formatted as
        // a SocketAddr rather than composed textually.
        let tmp = TempDir::new().unwrap();
        let mut cfg = sample_config();
        cfg.network.bootnodes = vec![enode("[2001:db8::2]:30303")];
        cfg.node.external_ip = "2001:db8::7".parse().unwrap();

        let (_candidate_dir, candidate) = pinned_candidate();
        write_service_configs(tmp.path(), &candidate, &cfg)
            .await
            .unwrap();

        let env = std::fs::read_to_string(tmp.path().join("summit.env")).unwrap();
        assert_eq!(env, "SUMMIT_ADVERTISED_ADDR=[2001:db8::7]:18551\n");
    }

    #[tokio::test]
    async fn writes_network_manifest_verbatim() {
        let tmp = TempDir::new().unwrap();
        let mut cfg = sample_config();
        // A valid manifest with a non-canonical byte (trailing newline): the
        // written file must be the decoded bytes exactly, not a re-rendering.
        let raw = [
            include_bytes!("../../../crates/network-manifest/fixtures/network-manifest-v1.json")
                .as_slice(),
            b"\n",
        ]
        .concat();
        cfg.network = NetworkConfig {
            manifest_base64: base64::engine::general_purpose::STANDARD.encode(&raw),
            ..cfg.network
        };

        let (_candidate_dir, candidate) = pinned_candidate();
        write_service_configs(tmp.path(), &candidate, &cfg)
            .await
            .unwrap();

        let written = std::fs::read(tmp.path().join("network-manifest.json")).unwrap();
        assert_eq!(written, raw);
    }

    #[tokio::test]
    async fn writes_reth_genesis_verbatim() {
        let tmp = TempDir::new().unwrap();
        let cfg = sample_config();

        let (_candidate_dir, candidate) = pinned_candidate();
        write_service_configs(tmp.path(), &candidate, &cfg)
            .await
            .unwrap();

        let written = std::fs::read(tmp.path().join("reth-genesis.json")).unwrap();
        let expected =
            crate::reth_genesis::tests::genesis_json(crate::reth_genesis::tests::FIXTURE_CHAIN_ID);
        assert_eq!(written, expected);
    }

    #[tokio::test]
    async fn writes_summit_genesis_verbatim() {
        let tmp = TempDir::new().unwrap();
        let cfg = sample_config();

        let (_candidate_dir, candidate) = pinned_candidate();
        write_service_configs(tmp.path(), &candidate, &cfg)
            .await
            .unwrap();

        let written = std::fs::read(tmp.path().join("summit-genesis.toml")).unwrap();
        let expected = crate::summit_genesis::tests::genesis_toml(
            crate::summit_genesis::tests::FIXTURE_NAMESPACE,
        );
        assert_eq!(written, expected);
    }

    #[tokio::test]
    async fn sets_default_mode() {
        let tmp = TempDir::new().unwrap();
        let cfg = sample_config();

        let (_candidate_dir, candidate) = pinned_candidate();
        write_service_configs(tmp.path(), &candidate, &cfg)
            .await
            .unwrap();

        for name in [
            "domain.env",
            "attestation.env",
            "reth-p2p.env",
            "summit.env",
        ] {
            let meta = std::fs::metadata(tmp.path().join(name)).unwrap();
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(mode, DEFAULT_FILE_MODE);
        }
    }
}
