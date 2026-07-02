//! Hand off LUKS-related derived keys to `setup-persistent-luks` at startup. See
//! https://github.com/SeismicSystems/seismic-images/blob/29bb1f4e39/modules/seismic/mkosi.extra/usr/bin/setup-persistent-luks
//!
//! Writes 64 raw bytes — `storage_key (32B) || header_mac_key (32B)` —
//! to a tmpfs file owned by the enclave user. The LUKS-setup script
//! reads the file, uses both keys, and `shred -u`s the file after
//! `cryptsetup open` succeeds. The directory itself is created by
//! systemd's `RuntimeDirectory=` in enclave.service before this
//! process starts.

use crate::key_manager::{KeyManager, KeyPurpose};
use anyhow::{Context as _, Result};
use std::{fs, fs::OpenOptions, io::Write as _, os::unix::fs::OpenOptionsExt as _, path::Path};
use tracing::info;

/// Drop-zone for the LUKS keys. Hardcoded to match the `RuntimeDirectory=`
/// in enclave.service (seismic-images); the parent dir is created by
/// systemd before this process starts.
const LUKS_KEYS_PATH: &str = "/run/seismic/enclave/luks-keys";

/// Storage and header-MAC keys are pinned at epoch 0; they are never rotated.
const KEYS_EPOCH_0: u64 = 0;

/// Derive `storage_key` + `header_mac_key` from the current root_key
/// and write them to a tmpfs file for setup-persistent-luks to read.
/// Errors are fatal: without these keys reaching the LUKS-setup script,
/// `/persistent` won't mount and the node can't proceed.
pub fn write_keys_for_luks_setup(km: &KeyManager) -> Result<()> {
    let storage_key = km.derive_purpose_key(KeyPurpose::Storage, KEYS_EPOCH_0)?;
    let header_mac_key = km.derive_purpose_key(KeyPurpose::LuksHeaderMac, KEYS_EPOCH_0)?;

    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(storage_key.as_ref());
    buf[32..].copy_from_slice(header_mac_key.as_ref());

    // Write to a tmp file and rename into place: the consumer script `setup-persistent-luks`
    // polls for this exact path, so it must never observe a partially-written file.
    let path = Path::new(LUKS_KEYS_PATH);
    let tmp = path.with_extension("tmp");
    // delete in case a previous run left a tmp file (crashed before deleting it)
    let _ = fs::remove_file(&tmp);
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(&tmp)
        .with_context(|| format!("creating {}", tmp.display()))?;
    f.write_all(&buf)?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, path).with_context(|| format!("renaming {} into place", tmp.display()))?;
    info!(
        "wrote LUKS keys for setup-persistent-luks at {}",
        path.display()
    );
    Ok(())
}
