use crate::error::{Result, TdxInitError};
use crate::utils::file::{set_ownership, write_file_with_perms};
use std::fs::DirBuilder;
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use tracing::info;

const SSH_DIR: &str = "/home/searcher/.ssh";
const KEY_FILE: &str = "/etc/searcher_key";

const SSH_DIR_MODE: u32 = 0o700;
const AUTH_KEYS_MODE: u32 = 0o600;
const KEY_FILE_MODE: u32 = 0o600;

const SEARCHER_UID: u32 = 1000;
const SEARCHER_GID: u32 = 1000;

const SSH_KEY_RESTRICTIONS: &str = "no-port-forwarding,no-agent-forwarding,no-X11-forwarding";
const SSH_KEY_TYPE: &str = "ssh-ed25519";

pub fn build_auth_keys_content(keys: &[String]) -> String {
    keys.iter()
        .map(|key| format!("{} {} {}", SSH_KEY_RESTRICTIONS, SSH_KEY_TYPE, key))
        .collect::<Vec<String>>()
        .join("\n")
        + "\n"
}

pub fn create_ssh_dir() -> Result<()> {
    DirBuilder::new()
        .mode(SSH_DIR_MODE)
        .recursive(true)
        .create(PathBuf::from(SSH_DIR).as_path())
        .map_err(TdxInitError::Io)?;
    Ok(())
}

pub async fn write_keys(keys: &[String]) -> Result<()> {
    if keys.is_empty() {
        return Err(TdxInitError::EmptyKeys);
    }

    let ssh_dir = PathBuf::from(SSH_DIR);

    create_ssh_dir()?;
    set_ownership(&ssh_dir, SEARCHER_UID, SEARCHER_GID).await?;

    let auth_keys_content = build_auth_keys_content(keys);
    let auth_keys_path = ssh_dir.join("authorized_keys");

    write_file_with_perms(&auth_keys_path, &auth_keys_content, AUTH_KEYS_MODE).await?;
    set_ownership(&auth_keys_path, SEARCHER_UID, SEARCHER_GID).await?;

    write_file_with_perms(KEY_FILE, &keys[0], KEY_FILE_MODE).await?;

    info!("Wrote {} SSH key(s) to authorized_keys", keys.len());
    Ok(())
}
