use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use seismic_summit_key_holder::control::{self, DEFAULT_CONTROL_SOCKET_PATH};
use seismic_summit_key_holder::http;
use seismic_summit_key_holder::state::Holder;
use tracing::info;
use tracing_subscriber::EnvFilter;

/// Where the holder serves `{pubkeys, quote}`. `0.0.0.0`: deploy's harvest
/// dials in from outside; the node NSG restricts the port to
/// `operator_ip_cidr`, permanently (the quote window reopens every boot).
const DEFAULT_LISTEN_ADDR: &str = "0.0.0.0:7879";

/// Summit's keystore, on the LUKS-backed persistent volume
/// (`/persistent/summit` is 0700 summit:summit per seismic-images'
/// tmpfiles-persistent.conf). Does not exist until LUKS opens; the holder
/// serves RAM keys until then.
const DEFAULT_KEYSTORE_DIR: &str = "/persistent/summit/keys";

/// Where tdx-init drops the verbatim manifest. Mirrors tdx-init's
/// `CONF_DIR`/`network-manifest.json`; its presence closes the quote
/// window for this boot.
const NETWORK_MANIFEST_PATH: &str = "/run/seismic/conf/network-manifest.json";

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate summit keys in RAM and serve them: `{pubkeys, quote}` over
    /// HTTP for deploy's founding harvest, plus the persist control socket.
    Serve {
        /// HTTP listen address.
        #[arg(long, default_value = DEFAULT_LISTEN_ADDR)]
        listen: String,
        /// Summit keystore directory the persist op writes into.
        #[arg(long, default_value = DEFAULT_KEYSTORE_DIR)]
        keystore_dir: PathBuf,
        /// Persist control socket path.
        #[arg(long, default_value = DEFAULT_CONTROL_SOCKET_PATH)]
        control_socket: PathBuf,
        /// Network manifest path whose presence closes the quote window.
        #[arg(long, default_value = NETWORK_MANIFEST_PATH)]
        network_manifest: PathBuf,
    },
    /// Block until the holder has written the keystore (first boot) or
    /// confirmed it already exists (reboot). summit.service's
    /// ExecStartPre — the sole provisioner of summit's keystore, so a
    /// definitive failure exits nonzero and fails summit's start loudly
    /// rather than letting it run on keys the manifest never pinned.
    PersistWait {
        /// Persist control socket path.
        #[arg(long, default_value = DEFAULT_CONTROL_SOCKET_PATH)]
        control_socket: PathBuf,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    match Args::parse().command {
        Command::Serve {
            listen,
            keystore_dir,
            control_socket,
            network_manifest,
        } => serve(listen, keystore_dir, control_socket, network_manifest).await,
        Command::PersistWait { control_socket } => {
            let response = control::persist_wait(&control_socket).await?;
            info!("persist complete: {response:?}");
            Ok(())
        }
    }
}

async fn serve(
    listen: String,
    keystore_dir: PathBuf,
    control_socket: PathBuf,
    network_manifest: PathBuf,
) -> anyhow::Result<()> {
    let holder = Arc::new(Holder::new(keystore_dir, network_manifest));
    let keys = holder.public_keys()?;
    info!(
        node_public_key = %keys.node_hex(),
        consensus_public_key = %keys.consensus_hex(),
        "summit keys held"
    );

    let control_listener = control::bind(&control_socket)?;
    let http_listener = tokio::net::TcpListener::bind(&listen).await?;
    info!("HTTP listening on {listen}");

    tokio::select! {
        result = axum::serve(http_listener, http::router(Arc::clone(&holder))) => {
            result?;
            anyhow::bail!("HTTP server exited unexpectedly");
        }
        _ = control::serve(control_listener, holder) => {
            unreachable!("the control accept loop never returns");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory as _;

    #[test]
    fn args_parse() {
        Args::command().debug_assert();
    }
}
