//! Load-or-generate persistence for the standalone root key.
//!
//! The TDX custodian keeps its root key RAM-only and recovers it from peers
//! through the attested bootstrap; this service runs standalone with no
//! peers, so the root key lives in a local keyfile instead. Restarts must
//! re-derive the same epoch-0 keys and the same council inbox key (persisted
//! delivery envelopes decrypt against it), so the keyfile is the one piece
//! of state the operator must back up and protect.

use anyhow::{Context as _, Result, anyhow};
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;
use tracing::info;

/// Read the 32-byte root key from `path`, or generate one from the OS CSPRNG
/// and durably write it (mode 0600) on first boot.
pub fn load_or_generate(path: &Path) -> Result<[u8; 32]> {
    match fs::read(path) {
        Ok(bytes) => {
            let key: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow!("{} is not exactly 32 bytes", path.display()))?;
            info!(path = %path.display(), "loaded root key");
            Ok(key)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let key = generate_and_write(path)?;
            info!(path = %path.display(), "generated a fresh root key");
            Ok(key)
        }
        Err(e) => Err(e).with_context(|| format!("reading root key {}", path.display())),
    }
}

fn generate_and_write(path: &Path) -> Result<[u8; 32]> {
    use rand::{TryRngCore as _, rngs::OsRng};
    let mut key = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut key)
        .context("OS RNG must produce a root key")?;

    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating root key dir {}", parent.display()))?;
    }
    // create_new: if two instances race, or a partial file appeared some
    // other way, fail loudly rather than overwrite key material.
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating root key file {}", path.display()))?;
    file.write_all(&key).context("writing root key")?;
    file.sync_all().context("syncing root key")?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn generates_then_reloads_the_same_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys/root.key");
        let generated = load_or_generate(&path).unwrap();
        let reloaded = load_or_generate(&path).unwrap();
        assert_eq!(generated, reloaded);
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn rejects_a_wrong_size_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("root.key");
        fs::write(&path, [0u8; 16]).unwrap();
        let error = load_or_generate(&path).unwrap_err();
        assert!(error.to_string().contains("not exactly 32 bytes"));
    }
}
