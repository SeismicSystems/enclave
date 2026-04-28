use crate::utils::file::{create_dir_safe, write_file_with_perms};
use crate::{config::InitConfig, error::Result, error::TdxInitError};
use std::path::Path;
use tracing::{info, warn};

pub const PERSISTENT_CONFIG_FILE: &str = "/persistent/conf/node.json";
const PERSISTENT_CONFIG_MODE: u32 = 0o644;

/// Write the operator-supplied InitConfig to /persistent/conf/node.json.
/// Caller must ensure /persistent is mounted first (handled by the
/// `persistent-luks-setup.service` ordering in seismic-images).
pub async fn write_persistent_config(config: &InitConfig) -> Result<()> {
    let path = Path::new(PERSISTENT_CONFIG_FILE);

    if let Some(parent) = path.parent()
        && !create_dir_safe(parent).await
    {
        warn!("could not create config directory: {:?}", parent);
    }

    let content = serde_json::to_string_pretty(config).map_err(TdxInitError::Json)?;
    write_file_with_perms(path, &content, PERSISTENT_CONFIG_MODE).await?;
    info!("config written to {}", PERSISTENT_CONFIG_FILE);
    Ok(())
}
