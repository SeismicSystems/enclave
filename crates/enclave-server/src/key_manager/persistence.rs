//! Disk persistence for `root_key`.
//!
//! `root_key` persists at `<data_dir>/root_key`. Default `data_dir` is
//! `/var/lib/enclave` (FHS). Production routes that path onto a
//! LUKS-encrypted mount via a `BindPaths=` entry in the systemd unit;
//! the binary is unaware of LUKS or `/persistent/`. Tests pass
//! `--data-dir <tempdir>`.
//!
//! # Threat model
//!
//! Adversary is a malicious hypervisor. We can't do much against it at
//! this layer — it can drop writes, lie about `fsync`, roll back the
//! disk, etc. Defenses against those live above this module (peer-fetch
//! fallback, future consensus-arbitrated bootstrap; see tee-plan.md
//! enclave TODO 3).
//!
//! This module's responsibility is narrower: write `root_key` once at
//! genesis (or first peer-fetch), read it on every subsequent boot.
//! Reads hard-fail on any wrong-size or unreadable file rather than
//! silently regenerating — silent regeneration is a chain-bricking
//! action. Writes are in-place (no temp file + rename); a crash in the
//! brief write window can leave a wrong-size file, which triggers the
//! same hard-fail. Production TDX VMs have no SSH, so "recovery" means
//! replacing the VM (Pulumi destroy + up); the fresh VM re-runs the
//! resolve-or-generate flow from scratch.

use anyhow::{Context as _, Result, anyhow};
use std::{
    fs::{self, OpenOptions},
    io::{self, Write as _},
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::Path,
};

const ROOT_KEY_FILENAME: &str = "root_key";
// 0o400 (owner read-only). We never rewrite this file — it's write-once at
// genesis (or first peer-fetch). The mode mostly defends against a future
// regression that accidentally opens it O_WRONLY: that would fail loudly
// with EACCES rather than silently clobbering the network's root key.
const ROOT_KEY_MODE: u32 = 0o400;

pub fn root_key_path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join(ROOT_KEY_FILENAME)
}

/// Read `root_key` from `data_dir/root_key`.
///
/// Returns `Ok(None)` if the file does not exist (first boot). Returns
/// `Err` on any other I/O failure or if the file is not exactly 32 bytes —
/// silently regenerating would be a chain-bricking action and demands
/// operator intervention.
pub fn read_root_key(data_dir: &Path) -> Result<Option<[u8; 32]>> {
    let path = root_key_path(data_dir);
    match fs::read(&path) {
        Ok(bytes) => {
            let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                anyhow!(
                    "root_key at {} has wrong size: expected 32 bytes, got {}",
                    path.display(),
                    bytes.len(),
                )
            })?;
            Ok(Some(arr))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading root_key at {}", path.display())),
    }
}

/// Write `root_key` to `data_dir/root_key` with mode 0400.
///
/// Recipe: `open(O_CREAT|O_EXCL)`, write 32 bytes, set mode 0400, fsync
/// the file, fsync the parent directory. Refuses to overwrite an existing
/// file (`O_EXCL`) — callers must check `read_root_key` first.
///
/// A crash between open and the final fsync can leave a wrong-size file
/// on disk; `read_root_key` hard-fails in that case and recovery is to
/// replace the VM (no SSH into production TDX). Acceptable because the
/// write window is microseconds for a 32-byte one-shot, and no client
/// has used the key yet at first-create time (the attestation endpoint
/// isn't serving until after this function returns).
///
/// See <https://danluu.com/file-consistency/> for the fsync recipe and
/// why each step matters.
pub fn write_root_key(data_dir: &Path, key: &[u8; 32]) -> Result<()> {
    let path = root_key_path(data_dir);

    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(ROOT_KEY_MODE)
        .open(&path)
        .with_context(|| format!("creating root_key at {}", path.display()))?;
    file.write_all(key).context("writing root_key bytes")?;
    // Defensive re-chmod in case the open-time umask widened the perms.
    file.set_permissions(fs::Permissions::from_mode(ROOT_KEY_MODE))
        .with_context(|| format!("setting mode {ROOT_KEY_MODE:o}"))?;
    file.sync_all().context("fsync on root_key")?;
    drop(file);

    fs::File::open(data_dir)
        .and_then(|f| f.sync_all())
        .with_context(|| format!("fsync on parent dir {}", data_dir.display()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn read_missing_returns_none() {
        let dir = tempdir().unwrap();
        assert!(read_root_key(dir.path()).unwrap().is_none());
    }

    #[test]
    fn write_then_read_roundtrips() {
        let dir = tempdir().unwrap();
        let key = [0xABu8; 32];
        write_root_key(dir.path(), &key).unwrap();
        let read = read_root_key(dir.path()).unwrap().unwrap();
        assert_eq!(read, key);
    }

    #[test]
    fn write_creates_file_with_mode_0400() {
        let dir = tempdir().unwrap();
        write_root_key(dir.path(), &[0u8; 32]).unwrap();
        let mode = fs::metadata(root_key_path(dir.path()))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, ROOT_KEY_MODE);
    }

    #[test]
    fn read_rejects_wrong_size_file() {
        let dir = tempdir().unwrap();
        fs::write(root_key_path(dir.path()), b"too short").unwrap();
        let err = read_root_key(dir.path()).unwrap_err();
        assert!(err.to_string().contains("wrong size"));
    }

    #[test]
    fn write_refuses_to_overwrite_existing() {
        let dir = tempdir().unwrap();
        write_root_key(dir.path(), &[0x11u8; 32]).unwrap();
        // O_EXCL: callers must check read_root_key first; this guards against
        // accidental clobbering of an existing key.
        assert!(write_root_key(dir.path(), &[0x22u8; 32]).is_err());
        assert_eq!(read_root_key(dir.path()).unwrap().unwrap(), [0x11u8; 32]);
    }

    #[test]
    fn write_to_missing_dir_errors() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("does-not-exist");
        assert!(write_root_key(&missing, &[0u8; 32]).is_err());
    }
}
