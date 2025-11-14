use crate::utils::file::{create_dir_safe, set_file_permissions_safe, write_file_with_perms};
use crate::{config::InitConfig, error::Result, error::TdxInitError};
use std::path::Path;
use tokio::fs;
use tracing::warn;

const TEMP_CONFIG_FILE: &str = "/etc/tdx-init/config.json";
const PERSISTENT_CONFIG_FILE: &str = "/persistent/conf/node.json";
const CONFIG_FILE_MODE: u32 = 0o600;
const PERSISTENT_CONFIG_MODE: u32 = 0o644;

pub async fn write_temp_config(config: &InitConfig) -> Result<()> {
    let config_path = Path::new(TEMP_CONFIG_FILE);

    if let Some(parent) = config_path.parent() {
        if !create_dir_safe(parent).await {
            warn!("Warning: Could not create config directory: {:?}", parent);
        }
    }

    let config_content = serde_json::to_string_pretty(config).map_err(TdxInitError::Json)?;

    write_file_with_perms(config_path, &config_content, CONFIG_FILE_MODE).await?;

    Ok(())
}

pub async fn read_temp_config() -> Result<InitConfig> {
    let config_content = fs::read_to_string(TEMP_CONFIG_FILE).await?;
    let config: InitConfig = serde_json::from_str(&config_content).map_err(TdxInitError::Json)?;
    Ok(config)
}

pub async fn copy_config_to_persistent(config: &InitConfig) -> Result<()> {
    let persistent_path = Path::new(PERSISTENT_CONFIG_FILE);

    if let Some(parent) = persistent_path.parent() {
        if !create_dir_safe(parent).await {
            warn!(
                "Warning: Could not create persistent config directory: {:?}",
                parent
            );
            return Ok(());
        }
    }

    let config_content = serde_json::to_string_pretty(config).map_err(TdxInitError::Json)?;

    match write_file_with_perms(persistent_path, &config_content, PERSISTENT_CONFIG_MODE).await {
        Ok(()) => {
            tracing::info!("Config copied to {}", PERSISTENT_CONFIG_FILE);
        }
        Err(e) => {
            warn!(
                "Warning: Could not copy config to persistent storage: {}",
                e
            );
        }
    }

    Ok(())
}
