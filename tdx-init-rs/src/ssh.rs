use crate::error::Result;
use crate::error::TdxInitError;
use nix::unistd::{chown, Gid, Uid};
use std::fs::DirBuilder;
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;

const SSH_DIR: &str = "/home/searcher/.ssh";
const SSH_DIR_OWNER: Uid = Uid::from_raw(1000);
const SSH_DIR_GROUP: Gid = Gid::from_raw(1000);

pub async fn write_keys(keys: &[String]) -> Result<()> {
    let ssh_dir = PathBuf::from(SSH_DIR);
    DirBuilder::new()
        .mode(0700)
        .recursive(true)
        .create(ssh_dir.as_path())
        .map_err(|e| TdxInitError::Io(e))?;

    chown(
        SSH_DIR,
        Some(SSH_DIR_OWNER),
        Some(SSH_DIR_GROUP),
    )
    .map_err(|e| TdxInitError::CommandError {
        cmd: format!("chown -R {SSH_DIR_OWNER}:{SSH_DIR_GROUP} {SSH_DIR}"),
        stderr: e.to_string(),
    })?;

    Ok(())
}
