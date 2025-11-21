use crate::config::{InitConfig, LuksToken};
use crate::error::{Result, TdxInitError};
use crate::utils::command::{execute_command, execute_command_with_stdin};
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::fs;
use tokio::process::Command;
use tracing::info;

pub const HEADER_FILE: &str = "/tmp/luks_header";
pub const MAPPER_NAME: &str = "persistent";
pub const MAPPER_DEVICE: &str = "/dev/mapper/persistent";

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
            log: None,
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

pub async fn format_luks_device(device_path: &PathBuf, passphrase: &str) -> Result<()> {
    info!("Formatting disk with LUKS2...");
    execute_command_with_stdin(
        "cryptsetup",
        &[
            "luksFormat",
            "--type",
            "luks2",
            "--header",
            HEADER_FILE,
            "--align-payload",
            "32769",
            "-q",
            device_path.to_str().unwrap(),
        ],
        passphrase.as_bytes(),
    )
    .await
}

pub async fn create_luks_token(ssh_key: &str, config_data: Option<String>) -> Result<LuksToken> {
    let mut user_data = HashMap::new();
    user_data.insert("ssh_key".to_string(), ssh_key.to_string());
    user_data.insert("metadata".to_string(), ssh_key.to_string());

    if let Some(config_data) = config_data {
        user_data.insert("config".to_string(), config_data);
        info!("Including configuration data in LUKS header");
    }

    Ok(LuksToken {
        token_type: "user".to_string(),
        keyslots: vec![],
        user_data,
    })
}

pub async fn import_luks_token(token: &LuksToken) -> Result<()> {
    let token_json = serde_json::to_string(token).map_err(TdxInitError::Json)?;

    info!("Saving searcher SSH key...");
    execute_command_with_stdin(
        "cryptsetup",
        &[
            "token",
            "import",
            "--token-id",
            "1",
            "--header",
            HEADER_FILE,
            "/dev/null",
        ],
        token_json.as_bytes(),
    )
    .await
}

pub async fn restore_header_to_device(device_path: &PathBuf) -> Result<()> {
    info!("Writing header to disk...");
    execute_command(
        "cryptsetup",
        &[
            "luksHeaderRestore",
            device_path.to_str().unwrap(),
            "--header-backup-file",
            HEADER_FILE,
        ],
    )
    .await
}

pub async fn backup_header_from_device(device_path: &PathBuf) -> Result<()> {
    info!("Extracting LUKS header...");
    execute_command(
        "cryptsetup",
        &[
            "luksHeaderBackup",
            device_path.to_str().unwrap(),
            "--header-backup-file",
            HEADER_FILE,
        ],
    )
    .await
}

pub async fn open_luks_container(device_path: &PathBuf, passphrase: &str) -> Result<()> {
    execute_command_with_stdin(
        "cryptsetup",
        &[
            "open",
            "--header",
            HEADER_FILE,
            device_path.to_str().unwrap(),
            MAPPER_NAME,
        ],
        passphrase.as_bytes(),
    )
    .await
}

pub async fn close_luks_container() -> Result<()> {
    execute_command("cryptsetup", &["close", MAPPER_NAME]).await
}

pub async fn cleanup_header_file() {
    let _ = fs::remove_file(HEADER_FILE).await;
}
