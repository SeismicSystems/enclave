use clap::{Parser, Subcommand};
use error::Result;
use std::path::Path;
use tokio::fs;
use tracing::info;

mod config;
mod error;
mod server;
mod writer;

const CONF_DIR: &str = "/persistent/conf";
/// Sentinel marking that the per-service config write completed.
/// On reboot, presence of this file short-circuits the HTTP server so
/// we don't re-listen for config that's already been delivered.
const SENTINEL_FILE: &str = "/persistent/conf/.tdx-init-done";

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
/// out per-component env files under [CONF_DIR]. Idempotent across
/// reboots: if the sentinel exists, exits immediately.
///
/// LUKS provisioning is no longer this binary's responsibility — see
/// seismic-images' `setup-persistent-luks` script + the
/// `persistent-luks-setup.service` unit, which run before this service
/// and ensure /persistent is already mounted by the time we get here.
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
