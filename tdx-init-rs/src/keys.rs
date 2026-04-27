use crate::error::Result;
use crate::persistence::{self, PERSISTENT_CONFIG_FILE};
use crate::server;
use tokio::fs;
use tracing::info;

/// Wait for an InitConfig to be POSTed by the operator, then write it to
/// `/persistent/conf/node.json`. Idempotent across reboots: if the config
/// file already exists, exits immediately.
///
/// LUKS provisioning is no longer this binary's responsibility — see
/// seismic-images' `setup-persistent-luks` script + the
/// `persistent-luks-setup.service` unit, which run before this service
/// and ensure /persistent is already mounted by the time we get here.
pub async fn wait_for_config() -> Result<()> {
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
    let config = server::http::run_initialization_server().await?;
    persistence::write_persistent_config(&config).await?;
    info!("configuration received and written to disk");
    Ok(())
}
