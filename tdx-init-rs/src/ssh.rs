use crate::error::Result;
use crate::error::TdxInitError;
use nix::unistd::{Gid, Uid, chown};
use std::fs::DirBuilder;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::PathBuf;
use tokio::fs;
use tracing::info;

const SSH_DIR: &str = "/home/searcher/.ssh";
const KEY_FILE: &str = "/etc/searcher_key";

const SSH_DIR_MODE: u32 = 0o700;
const AUTH_KEYS_MODE: u32 = 0o600;
const KEY_FILE_MODE: u32 = 0o600;

const SEARCHER_UID: u32 = 1000;
const SEARCHER_GID: u32 = 1000;

const SSH_DIR_OWNER: Uid = Uid::from_raw(SEARCHER_UID);
const SSH_DIR_GROUP: Gid = Gid::from_raw(SEARCHER_GID);
const AUTH_KEYS_OWNER: Uid = Uid::from_raw(SEARCHER_UID);
const AUTH_KEYS_GROUP: Gid = Gid::from_raw(SEARCHER_GID);

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
        .map_err(|e| TdxInitError::Io(e))?;
    Ok(())
}

pub fn set_ownership(path: &PathBuf, owner: Uid, group: Gid) -> Result<()> {
    chown(path.as_path(), Some(owner), Some(group)).map_err(|e| TdxInitError::CommandError {
        cmd: format!("chown {}:{} {path:?}", owner, group),
        stderr: e.to_string(),
    })?;
    Ok(())
}

async fn set_file_permissions(path: &PathBuf, mode: u32) -> Result<()> {
    let mut perms = fs::metadata(path).await?.permissions();
    perms.set_mode(mode);
    fs::set_permissions(path, perms).await?;
    Ok(())
}

pub async fn write_keys(keys: &[String]) -> Result<()> {
    if keys.is_empty() {
        return Err(TdxInitError::EmptyKeys);
    }

    let ssh_dir = PathBuf::from(SSH_DIR);

    // Create SSH directory first
    create_ssh_dir()?;
    set_ownership(&ssh_dir, SSH_DIR_OWNER, SSH_DIR_GROUP)?;

    let auth_keys_content = build_auth_keys_content(keys);
    let auth_keys_path = ssh_dir.join("authorized_keys");

    fs::write(&auth_keys_path, auth_keys_content).await?;
    set_file_permissions(&auth_keys_path, AUTH_KEYS_MODE).await?;
    set_ownership(&auth_keys_path, AUTH_KEYS_OWNER, AUTH_KEYS_GROUP)?;

    let key_file_path = PathBuf::from(KEY_FILE);
    fs::write(&key_file_path, &keys[0]).await?;
    set_file_permissions(&key_file_path, KEY_FILE_MODE).await?;

    info!("Wrote {} SSH key(s) to authorized_keys", keys.len());
    Ok(())
}
