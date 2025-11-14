use crate::config::{InitConfig, LuksToken};
use crate::error::Result;
use crate::error::TdxInitError;
use crate::{persistence, server, ssh};
use std::path::PathBuf;
use std::time::Duration;
use tokio::process::Command;
use tracing::info;

pub async fn wait_for_key(device_path: PathBuf) -> Result<()> {
    if is_luks_device(&device_path).await? {
        info!("Found existing LUKS container, extracting config...");
        let config = extract_config(&device_path).await?;
        ssh::write_keys(&config.ssh_keys).await?;
        persistence::write_temp_config(&config).await?;
        info!(
            "{} SSH key(s) extracted from LUKS header",
            config.ssh_keys.len()
        );
    } else {
        info!("No LUKS container found, starting HTTP server on port 8080...");
        let config = server::run_initialization_server().await?;
        ssh::write_keys(&config.ssh_keys).await?;
        persistence::write_temp_config(&config).await?;

        tokio::time::sleep(Duration::from_millis(100)).await;
        let passphrase = generate_random_passphrase()?;
        initialize_with_passphrase(device_path, passphrase, &config).await?;

        info!("Configuration received via HTTP and written to disk!");
    }
    Ok(())
}

pub async fn set_passphrase(device_path: PathBuf) -> Result<()> {
    print!("Enter passphrase: ");
    use std::io::{self, Write};
    io::stdout().flush().unwrap();

    let mut passphrase = String::new();
    io::stdin().read_line(&mut passphrase)?;
    let passphrase = passphrase.trim().to_string();

    let config = persistence::read_temp_config().await?;
    initialize_with_passphrase(device_path, passphrase, &config).await?;

    Ok(())
}

pub async fn is_luks_device(device_path: &std::path::Path) -> Result<bool> {
    let cmd = Command::new("cryptsetup")
        .arg("isLuks")
        .arg(device_path.as_os_str())
        .output()
        .await
        .map_err(|e| TdxInitError::CommandError {
            cmd: "cryptsetup isLuks".to_string(),
            stderr: e.to_string(),
        })?;
    Ok(cmd.status.success())
}

pub async fn extract_config(device_path: &std::path::Path) -> Result<InitConfig> {
    let token = extract_luks_token(device_path).await?;

    if let Some(config_data) = token.user_data.get("config") {
        let config: InitConfig = serde_json::from_str(config_data).map_err(TdxInitError::Json)?;
        return Ok(config);
    }

    if let Some(key_data) = token.user_data.get("metadata") {
        return Ok(InitConfig {
            ssh_keys: vec![key_data.clone()],
            domain: None,
            args: None,
        });
    }

    Err(TdxInitError::ConfigNotFound(
        "config or metadata not found in LUKS token".to_string(),
    ))
}

pub async fn extract_luks_token(device_path: &std::path::Path) -> Result<LuksToken> {
    let cmd = Command::new("cryptsetup")
        .arg("token")
        .arg("export")
        .arg("--token-id")
        .arg("1")
        .arg(device_path.as_os_str())
        .output()
        .await
        .map_err(|e| TdxInitError::CommandError {
            cmd: "cryptsetup token export".to_string(),
            stderr: e.to_string(),
        })?;
    let token: LuksToken =
        serde_json::from_slice(&cmd.stdout).map_err(|e| TdxInitError::Json(e))?;
    Ok(token)
}

pub fn generate_random_passphrase() -> Result<String> {
    todo!("Implement passphrase generation")
}

pub async fn initialize_with_passphrase(
    _device_path: PathBuf,
    _passphrase: String,
    _config: &InitConfig,
) -> Result<()> {
    todo!("Implement LUKS initialization")
}
