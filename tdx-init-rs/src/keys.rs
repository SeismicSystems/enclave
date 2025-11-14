use crate::error::Result;
use crate::luks;
use crate::ssh;
use crate::persistence;
use crate::server;
use crate::passphrase;
use std::path::PathBuf;
use std::time::Duration;
use tracing::info;

pub async fn wait_for_key(device_path: PathBuf) -> Result<()> {
    if luks::is_luks_device(&device_path).await? {
        info!("Found existing LUKS container, extracting config...");
        let config = luks::extract_config(&device_path).await?;
        ssh::write_keys(&config.ssh_keys).await?;
        persistence::write_temp_config(&config).await?;
        info!("{} SSH key(s) extracted from LUKS header", config.ssh_keys.len());
    } else {
        info!("No LUKS container found, starting HTTP server on port 8080...");
        let config = server::http::run_initialization_server().await?;
        ssh::write_keys(&config.ssh_keys).await?;
        persistence::write_temp_config(&config).await?;

        tokio::time::sleep(Duration::from_millis(100)).await;
        let passphrase = passphrase::generate_random_passphrase()?;
        passphrase::initialize_with_passphrase(device_path, passphrase, &config).await?;

        info!("Configuration received via HTTP and written to disk!");
    }
    Ok(())
}

