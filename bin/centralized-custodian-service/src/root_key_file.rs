//! Keyfile persistence for the standalone custodian's root key.
//!
//! When no keyfile exists ([`load_or_default`]), every node falls back to
//! the same PUBLICLY KNOWN default (a hash of a fixed label, reproducible by
//! anyone from this source). That is deliberate: all nodes of the
//! centralized phase agree on epoch-0 keys with zero coordination, at the
//! cost that epoch 0 provides no confidentiality — the council must rotate
//! to a delivered epoch 1 immediately after launch. An operator who wants a
//! secret root key instead pre-places 32 random bytes at the path before
//! first boot.

use anyhow::{Context as _, Result, anyhow};
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;
use tracing::{info, warn};

/// `SHA256("seismic-centralized-default-root-key-v1")` — public by
/// construction; see the module docs for why that is acceptable at epoch 0
/// and nowhere else.
pub const DEFAULT_ROOT_KEY: [u8; 32] = [
    0x31, 0xfb, 0x87, 0x02, 0x14, 0xe3, 0xb0, 0x5b, 0x6c, 0xa9, 0xe2, 0x4c, 0x3e, 0xbb, 0x0c, 0x0d,
    0xd3, 0x81, 0xff, 0x78, 0x00, 0xb3, 0x87, 0xb3, 0xda, 0xd8, 0x16, 0xaf, 0xcb, 0x0f, 0xf7, 0xa0,
];

/// Read the 32-byte root key from `path`; if absent, durably write the
/// publicly known [`DEFAULT_ROOT_KEY`] there (so the choice is pinned and
/// survives changes to this constant) and use it. Warns loudly whenever the
/// key in use is the default.
pub fn load_or_default(path: &Path) -> Result<[u8; 32]> {
    let key = match fs::read(path) {
        Ok(bytes) => {
            let key: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow!("{} is not exactly 32 bytes", path.display()))?;
            info!(path = %path.display(), "loaded root key");
            key
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            write_key_file(path, &DEFAULT_ROOT_KEY)?;
            info!(path = %path.display(), "no root keyfile; pinned the shared default");
            DEFAULT_ROOT_KEY
        }
        Err(e) => {
            return Err(e).with_context(|| format!("reading root key {}", path.display()));
        }
    };
    if key == DEFAULT_ROOT_KEY {
        warn!(
            "using the PUBLICLY KNOWN default root key: epoch-0 keys provide no \
             confidentiality — deliver epoch 1 via the council immediately"
        );
    }
    Ok(key)
}

/// Read an existing 32-byte root keyfile; `Ok(None)` if absent. The
/// observer-mode read path: an observer must never pin the public default
/// (its root key comes from the parent), so it never calls
/// [`load_or_default`].
pub fn load_existing(path: &Path) -> Result<Option<[u8; 32]>> {
    match fs::read(path) {
        Ok(bytes) => {
            let key: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow!("{} is not exactly 32 bytes", path.display()))?;
            info!(path = %path.display(), "loaded root key");
            Ok(Some(key))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading root key {}", path.display())),
    }
}

/// Durably create the keyfile with a known key (the observer-mode
/// persistence path for a parent-fetched root key). `create_new` semantics:
/// errors if the file already exists.
pub fn write_new(path: &Path, key: &[u8; 32]) -> Result<()> {
    write_key_file(path, key)
}

fn write_key_file(path: &Path, key: &[u8; 32]) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating key dir {}", parent.display()))?;
    }
    // create_new: if two instances race, or a partial file appeared some
    // other way, fail loudly rather than overwrite key material.
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating key file {}", path.display()))?;
    file.write_all(key).context("writing key file")?;
    file.sync_all().context("syncing key file")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn absent_root_keyfile_pins_the_shared_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys/root.key");
        assert_eq!(load_or_default(&path).unwrap(), DEFAULT_ROOT_KEY);
        // The default was pinned to disk, mode 0600.
        assert_eq!(fs::read(&path).unwrap(), DEFAULT_ROOT_KEY);
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        // Two "nodes" with no keyfile agree.
        let other = dir.path().join("other/root.key");
        assert_eq!(load_or_default(&other).unwrap(), DEFAULT_ROOT_KEY);
    }

    #[test]
    fn preplaced_root_keyfile_wins_over_the_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("root.key");
        fs::write(&path, [0xAB; 32]).unwrap();
        assert_eq!(load_or_default(&path).unwrap(), [0xAB; 32]);
    }

    #[test]
    fn rejects_a_wrong_size_root_keyfile() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("root.key");
        fs::write(&path, [0u8; 16]).unwrap();
        let error = load_or_default(&path).unwrap_err();
        assert!(error.to_string().contains("not exactly 32 bytes"));
    }
}
