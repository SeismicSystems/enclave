use clap::{Parser, Subcommand};
use error::Result;
use std::path::Path;
use tokio::fs;
use tracing::info;

mod config;
mod error;
mod manifest;
mod peers;
mod reth_genesis;
mod server;
mod summit_genesis;
mod writer;

/// Per-service env file drop-zone. Lives on tmpfs (cleared each boot),
/// reachable before /persistent is mounted. The directory itself is
/// created by `systemd-tmpfiles` from a snippet shipped in seismic-images;
/// this binary only writes into it.
pub(crate) const CONF_DIR: &str = "/run/seismic/conf";
/// Sentinel marking that the per-service config write completed.
/// Lives under [`CONF_DIR`] (tmpfs, cleared each boot), so the binary
/// always blocks for a fresh POST on subsequent boots — deploy tooling
/// re-supplies the config every time. The sentinel still gates against
/// multiple POSTs within a single boot (e.g. manual `systemctl restart`).
const SENTINEL_FILE: &str = "/run/seismic/conf/.tdx-init-done";

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Wait for an InitConfig POST and translate it into per-service env
    /// files under [CONF_DIR]. Exits immediately on subsequent boots
    /// (sentinel file present).
    WaitForConfig,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    match args.command {
        Command::WaitForConfig => wait_for_and_persist_config().await,
    }
}

/// Wait for an InitConfig (TOML) to be POSTed by the operator, then fan
/// out per-component env files under [CONF_DIR]. Outputs go to /run
/// (tmpfs), so the binary re-derives them on every boot; deploy tooling
/// re-POSTs each time. The sentinel only gates against multiple POSTs
/// within a single boot.
async fn wait_for_and_persist_config() -> Result<()> {
    if fs::try_exists(SENTINEL_FILE).await? {
        info!(
            "config already delivered (sentinel {} present); nothing to do",
            SENTINEL_FILE,
        );
        return Ok(());
    }

    info!(
        "no sentinel at {}; starting HTTP server on port 8080",
        SENTINEL_FILE,
    );
    let config = server::run_initialization_server().await?;

    let conf_dir = Path::new(CONF_DIR);
    writer::write_service_configs(conf_dir, &config).await?;
    fs::write(SENTINEL_FILE, b"").await?;
    info!("configuration received and written under {}", CONF_DIR);
    Ok(())
}
