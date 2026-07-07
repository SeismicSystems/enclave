//! Hand off LUKS-related derived keys to `setup-persistent-luks` at startup. See
//! https://github.com/SeismicSystems/seismic-images/blob/29bb1f4e39/modules/seismic/mkosi.extra/usr/bin/setup-persistent-luks
//!
//! The custodian writes 64 raw bytes — `storage_key (32B) || header_mac_key
//! (32B)` — to a tmpfs file owned by the enclave user. The LUKS-setup script
//! reads the file, uses both keys, and `shred -u`s the file after
//! `cryptsetup open` succeeds. The directory itself is created by systemd's
//! `RuntimeDirectory=` in enclave.service before this process starts.

use anyhow::Result;
use seismic_key_custodian::Custodian;
use std::path::Path;
use tracing::info;

/// Drop-zone for the LUKS keys. Hardcoded to match the `RuntimeDirectory=`
/// in enclave.service (seismic-images); the parent dir is created by
/// systemd before this process starts.
const LUKS_KEYS_PATH: &str = "/run/seismic/enclave/luks-keys";

/// Have the custodian write the LUKS keyfile to the agreed drop-zone.
/// Errors are fatal: without these keys reaching the LUKS-setup script,
/// `/persistent` won't mount and the node can't proceed.
pub fn write_keys_for_luks_setup(custodian: &Custodian) -> Result<()> {
    custodian.write_luks_keyfile(Path::new(LUKS_KEYS_PATH))?;
    info!("wrote LUKS keys for setup-persistent-luks at {LUKS_KEYS_PATH}");
    Ok(())
}
