//! Export of the LUKS keyfile consumed by the persistent-disk setup path.

use crate::custodian::{Custodian, KeyPurpose};
use anyhow::{Context as _, Result};
use std::{fs, fs::OpenOptions, io::Write as _, os::unix::fs::OpenOptionsExt as _, path::Path};
use zeroize::Zeroizing;

/// Storage and header-MAC keys are pinned at epoch 0; they are never rotated.
const KEYS_EPOCH_0: u64 = 0;

impl Custodian {
    /// Derive the LUKS keys and write them to `path` as 64 raw bytes —
    /// `storage_key (32B) || header_mac_key (32B)` — mode 0400.
    ///
    /// Writes to a sibling tmp file and renames into place: consumers poll
    /// for the exact path, so they must never observe a partially-written
    /// file. Where the file goes, and who reads and shreds it, is the
    /// caller's deployment contract.
    pub fn write_luks_keyfile(&self, path: &Path) -> Result<()> {
        let storage_key: [u8; 32] = self.expand_purpose(KeyPurpose::Storage, KEYS_EPOCH_0);
        let header_mac_key: [u8; 32] = self.expand_purpose(KeyPurpose::LuksHeaderMac, KEYS_EPOCH_0);

        // The assembled image is the longest-lived copy this process keeps,
        // and it leaves as a file; scrub it when the write is done.
        let mut buf = Zeroizing::new([0u8; 64]);
        buf[..32].copy_from_slice(&storage_key);
        buf[32..].copy_from_slice(&header_mac_key);

        let tmp = path.with_extension("tmp");
        // delete in case a previous run left a tmp file (crashed before deleting it)
        let _ = fs::remove_file(&tmp);
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .open(&tmp)
            .with_context(|| format!("creating {}", tmp.display()))?;
        f.write_all(buf.as_slice())?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, path).with_context(|| format!("renaming {} into place", tmp.display()))?;
        Ok(())
    }
}
