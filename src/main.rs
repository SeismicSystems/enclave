use clap::{Parser, Subcommand};
use config::InitConfig;
use error::{Result, TdxInitError};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tokio::fs;
use tracing::{info, warn};

mod config;
mod error;
mod server;

const PERSISTENT_CONFIG_FILE: &str = "/persistent/conf/node.json";
// TODO: ownership and permissions on this file should be a seismic-images
// concern (User= + ExecStartPre/Post in tdx-init.service), not baked into
// the binary. Today tdx-init runs as root and we explicitly chmod to 0o644;
// the cleaner shape is to run tdx-init as a tdx-init:eth system user, let
// the default umask produce 0o644, and stop setting mode here.
const PERSISTENT_CONFIG_MODE: u32 = 0o644;

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Wait for an InitConfig POST and write it to [PERSISTENT_CONFIG_FILE].
    /// Exits immediately if the config file already exists (subsequent boots).
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

/// Wait for an InitConfig to be POSTed by the operator, then write it to
/// [PERSISTENT_CONFIG_FILE]. Idempotent across reboots: if the config
/// file already exists, exits immediately.
///
/// LUKS provisioning is no longer this binary's responsibility — see
/// seismic-images' `setup-persistent-luks` script + the
/// `persistent-luks-setup.service` unit, which run before this service
/// and ensure /persistent is already mounted by the time we get here.
async fn wait_for_and_persist_config() -> Result<()> {
    if fs::try_exists(PERSISTENT_CONFIG_FILE).await? {
        info!(
            "config already present at {}; nothing to do",
            PERSISTENT_CONFIG_FILE,
        );
        return Ok(());
    }

    info!(
        "no config at {}; starting HTTP server on port 8080",
        PERSISTENT_CONFIG_FILE,
    );
    let config = server::run_initialization_server().await?;
    write_persistent_config(&config).await?;
    info!("configuration received and written to disk");
    Ok(())
}

/// Write the operator-supplied InitConfig to [PERSISTENT_CONFIG_FILE].
/// Caller must ensure /persistent is mounted first (handled by the
/// `persistent-luks-setup.service` ordering in seismic-images).
async fn write_persistent_config(config: &InitConfig) -> Result<()> {
    let path = Path::new(PERSISTENT_CONFIG_FILE);

    if let Some(parent) = path.parent()
        && let Err(e) = fs::create_dir_all(parent).await
    {
        warn!("could not create config directory {:?}: {}", parent, e);
    }

    let content = serde_json::to_string_pretty(config).map_err(TdxInitError::Json)?;
    fs::write(path, &content).await?;
    let mut perms = fs::metadata(path).await?.permissions();
    perms.set_mode(PERSISTENT_CONFIG_MODE);
    fs::set_permissions(path, perms).await?;
    info!("config written to {}", PERSISTENT_CONFIG_FILE);
    Ok(())
}
