//! Reading the master node seed from a summit keystore directory.
//!
//! Summit's keystore is a directory holding `node_key.pem` — despite the
//! name, the file is hex text (optionally `0x`-prefixed, whitespace
//! tolerated), decoding to the 32-byte ed25519 seed. The parsing here
//! matches commonware's `from_hex_formatted`, which summit uses to read the
//! same file.

use anyhow::{Context as _, Result, bail};
use std::path::Path;
use zeroize::{Zeroize as _, Zeroizing};

pub const NODE_KEY_FILE: &str = "node_key.pem";

/// Read `<dir>/node_key.pem` and decode the 32-byte master seed. Warns (but
/// does not reject, matching summit) if the file is group/other-accessible.
pub fn load_node_seed(summit_key_dir: &Path) -> Result<Zeroizing<[u8; 32]>> {
    let path = summit_key_dir.join(NODE_KEY_FILE);
    warn_if_permissions_too_open(&path);
    let mut text = std::fs::read_to_string(&path)
        .with_context(|| format!("reading node key {}", path.display()))?;

    // Tolerances match commonware_utils::from_hex_formatted.
    let mut cleaned = text.replace(['\t', '\n', '\r', ' '], "");
    text.zeroize();
    let hex_str = cleaned.strip_prefix("0x").unwrap_or(&cleaned);
    let decoded = match hex::decode(hex_str) {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(err) => {
            cleaned.zeroize();
            bail!("node key {} is not valid hex: {err}", path.display());
        }
    };
    cleaned.zeroize();

    let seed: [u8; 32] = decoded.as_slice().try_into().map_err(|_| {
        anyhow::anyhow!(
            "node key {} decodes to {} bytes, expected 32",
            path.display(),
            decoded.len()
        )
    })?;
    Ok(Zeroizing::new(seed))
}

fn warn_if_permissions_too_open(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if let Ok(metadata) = std::fs::metadata(path) {
            let mode = metadata.permissions().mode();
            if mode & 0o077 != 0 {
                tracing::warn!(
                    path = %path.display(),
                    mode = format!("{:o}", mode & 0o777),
                    "node key file is accessible by group/other"
                );
            }
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::master_public_from_seed;

    fn write_keystore(contents: &str) -> tempdir::TempDirGuard {
        tempdir::write_node_key(contents)
    }

    // Minimal tempdir helper without external deps.
    mod tempdir {
        use std::path::PathBuf;

        pub struct TempDirGuard(pub PathBuf);
        impl Drop for TempDirGuard {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        pub fn write_node_key(contents: &str) -> TempDirGuard {
            let dir = std::env::temp_dir().join(format!(
                "observer-key-test-{}-{:x}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join(super::NODE_KEY_FILE), contents).unwrap();
            TempDirGuard(dir)
        }
    }

    const SEED_HEX: &str = "0101010101010101010101010101010101010101010101010101010101010101";

    #[test]
    fn loads_plain_hex() {
        let dir = write_keystore(SEED_HEX);
        let seed = load_node_seed(&dir.0).unwrap();
        assert_eq!(*seed, [1u8; 32]);
        assert_eq!(
            hex::encode(master_public_from_seed(&seed)),
            "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"
        );
    }

    #[test]
    fn tolerates_prefix_and_whitespace() {
        let dir = write_keystore(&format!("0x{SEED_HEX}\n"));
        assert_eq!(*load_node_seed(&dir.0).unwrap(), [1u8; 32]);
    }

    #[test]
    fn rejects_bad_hex() {
        let dir = write_keystore("not hex at all");
        assert!(load_node_seed(&dir.0).is_err());
    }

    #[test]
    fn rejects_wrong_length() {
        let dir = write_keystore("0102");
        let err = load_node_seed(&dir.0).unwrap_err().to_string();
        assert!(err.contains("expected 32"), "{err}");
    }

    #[test]
    fn missing_file_errors() {
        let dir = write_keystore(SEED_HEX);
        std::fs::remove_file(dir.0.join(NODE_KEY_FILE)).unwrap();
        assert!(load_node_seed(&dir.0).is_err());
    }
}
