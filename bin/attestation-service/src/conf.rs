//! tdx-init's config drop-zone, as this service reads it: the wait for the
//! config POST, and the files the service takes from it.
//!
//! The service starts at boot so the founding harvest can serve before any
//! configuration exists. Everything past the harvest needs the POST, so the
//! main flow blocks here until tdx-init marks its files written, then reads
//! the root-key fetch list tdx-init derived from `[network].bootnodes`. The
//! network manifest beside it is loaded by [`crate::network`].

use std::path::Path;
use std::time::Duration;

use anyhow::{Context as _, Result};
use tracing::info;

/// Where tdx-init writes on a node; see tdx-init's README.
pub const DEFAULT_CONF_DIR: &str = "/run/seismic/conf";
/// tdx-init writes this after every other file in the dir.
pub const TDX_INIT_DONE_MARKER: &str = ".tdx-init-done";
/// `SEISMIC_ROOT_KEY_PEERS=<url>,<url>`.
pub const ATTESTATION_ENV: &str = "attestation.env";
/// The network manifest, verbatim.
pub const NETWORK_MANIFEST: &str = "network-manifest.json";

const PEERS_KEY: &str = "SEISMIC_ROOT_KEY_PEERS";
const MARKER_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Block until tdx-init's done marker exists in `conf_dir`, then return the
/// peer list it wrote there.
pub async fn await_config(conf_dir: &Path) -> Result<Vec<String>> {
    let marker = conf_dir.join(TDX_INIT_DONE_MARKER);
    let env_path = conf_dir.join(ATTESTATION_ENV);
    info!("Waiting for the config POST ({})", marker.display());
    while !tokio::fs::try_exists(&marker)
        .await
        .with_context(|| format!("checking {}", marker.display()))?
    {
        tokio::time::sleep(MARKER_POLL_INTERVAL).await;
    }
    let content = tokio::fs::read_to_string(&env_path)
        .await
        .with_context(|| format!("reading {}", env_path.display()))?;
    let peers = parse_root_key_peers(&content)
        .with_context(|| format!("parsing {}", env_path.display()))?;
    info!("Config received; {} root-key peer(s)", peers.len());
    Ok(peers)
}

/// The file holds one line, `SEISMIC_ROOT_KEY_PEERS=` and a comma-separated
/// list, empty on the genesis node.
fn parse_root_key_peers(content: &str) -> Result<Vec<String>> {
    let mut peers = None;
    for line in content.lines().filter(|line| !line.trim().is_empty()) {
        let (key, value) = line
            .split_once('=')
            .with_context(|| format!("not KEY=VALUE: {line:?}"))?;
        anyhow::ensure!(key == PEERS_KEY, "unexpected key {key:?}");
        anyhow::ensure!(peers.is_none(), "{PEERS_KEY} set twice");
        peers = Some(
            value
                .split(',')
                .filter(|peer| !peer.is_empty())
                .map(str::to_string)
                .collect(),
        );
    }
    peers.with_context(|| format!("{PEERS_KEY} missing"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tdx_init_output() {
        assert_eq!(
            parse_root_key_peers(
                "SEISMIC_ROOT_KEY_PEERS=http://10.0.0.1:7878,http://10.0.0.2:7878\n"
            )
            .unwrap(),
            ["http://10.0.0.1:7878", "http://10.0.0.2:7878"]
        );
        assert!(
            parse_root_key_peers("SEISMIC_ROOT_KEY_PEERS=\n")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn rejects_anything_else() {
        for content in [
            "",
            "SEISMIC_ROOT_KEY_PEERS\n",
            "OTHER=1\n",
            "SEISMIC_ROOT_KEY_PEERS=a\nSEISMIC_ROOT_KEY_PEERS=b\n",
        ] {
            assert!(parse_root_key_peers(content).is_err(), "{content:?}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn waits_for_the_marker() {
        let dir = tempfile::tempdir().unwrap();
        let wait = tokio::spawn({
            let conf_dir = dir.path().to_path_buf();
            async move { await_config(&conf_dir).await }
        });

        tokio::time::sleep(MARKER_POLL_INTERVAL * 3).await;
        assert!(!wait.is_finished());

        let env = "SEISMIC_ROOT_KEY_PEERS=http://10.0.0.1:7878\n";
        std::fs::write(dir.path().join(ATTESTATION_ENV), env).unwrap();
        std::fs::write(dir.path().join(TDX_INIT_DONE_MARKER), b"").unwrap();
        assert_eq!(wait.await.unwrap().unwrap(), ["http://10.0.0.1:7878"]);
    }
}
