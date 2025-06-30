use crate::key_manager::NetworkKeyProvider;
use seismic_enclave::crypto::{decrypt_file, encrypt_file};

use std::path::Path;

/// Encrypts a snapshot archive file using a predefined snapshot key.
///
/// This function encrypts a `.tar.lz4` snapshot file located in `input_dir` and
/// outputs an encrypted `.enc` file in the specified `output_dir`. The encryption
/// uses a key fetched via `get_snapshot_key()`, ensuring the snapshot can only be
/// decrypted by appropriate enclaves.
///
/// # Arguments
///
/// * `input_dir` - Directory containing the plaintext snapshot file.
/// * `output_dir` - Directory where the encrypted file should be written.
/// * `snapshot_file` - Filename of the snapshot file to encrypt (e.g., `snapshot.tar.lz4`).
///
/// # Returns
///
/// Returns `Ok(())` if the encryption succeeds, or an `anyhow::Error` if the file is missing
/// or encryption fails.
///
/// # Errors
///
/// This function returns an error if:
/// - The input snapshot file does not exist.
/// - Encryption fails due to an internal error in the encryption process.
pub fn encrypt_snapshot(
    kp: &impl NetworkKeyProvider,
    epoch: u64,
    input_dir: &str,
    output_dir: &str,
    snapshot_file: &str,
) -> Result<(), anyhow::Error> {
    let input_path = &format!("{}/{}", input_dir, snapshot_file);
    let output_path = &format!("{}/{}.enc", output_dir, snapshot_file);

    // confirm that the snapshot file exists
    if !Path::new(&input_path).exists() {
        anyhow::bail!(
            "Snapshot file not found at expected path: {:?}",
            &input_path
        );
    }

    let snapshot_key = kp.get_snapshot_key(epoch);
    encrypt_file(&input_path, &output_path, &snapshot_key)
        .map_err(|e| anyhow::anyhow!("Failed to encrypt snapshot file: {:?}", e))?;

    Ok(())
}

/// Decrypts an encrypted snapshot archive file using a predefined snapshot key.
///
/// This function decrypts an `.enc` file located in `input_dir` and writes the
/// resulting `.tar.lz4` file into the specified `output_dir`. The decryption key
/// is fetched via `get_snapshot_key()`, which must match the key used during encryption.
///
/// # Arguments
///
/// * `input_dir` - Directory containing the encrypted snapshot file (e.g., `snapshot.tar.lz4.enc`).
/// * `output_dir` - Directory where the decrypted snapshot file should be saved.
/// * `snapshot_file` - Base filename of the snapshot archive (without `.enc` suffix).
///
/// # Returns
///
/// Returns `Ok(())` if decryption succeeds, or an `anyhow::Error` if the file is missing
/// or decryption fails.
///
/// # Errors
///
/// This function returns an error if:
/// - The encrypted snapshot file does not exist.
/// - Decryption fails due to an incorrect or unavailable key, or an internal decryption error.
pub fn decrypt_snapshot(
    kp: &impl NetworkKeyProvider,
    epoch: u64,
    input_dir: &str,
    output_dir: &str,
    snapshot_file: &str,
) -> Result<(), anyhow::Error> {
    let input_path = &format!("{}/{}.enc", input_dir, snapshot_file);
    let output_path = &format!("{}/{}", output_dir, snapshot_file);

    // confirm that the snapshot file exists
    if !Path::new(&input_path).exists() {
        anyhow::bail!(
            "Encrypted Snapshot file not found at expected path: {:?}",
            &input_path
        );
    }

    let snapshot_key = kp.get_snapshot_key(epoch);
    decrypt_file(&input_path, &output_path, &snapshot_key)
        .map_err(|e| anyhow::anyhow!("Failed to decrypt snapshot file: {:?}", e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_manager::KeyManagerBuilder;
    use crate::snapshot::SNAPSHOT_FILE;
    use crate::utils::test_utils::{generate_dummy_file, read_first_n_bytes};

    use anyhow::Error;
    use std::fs;
    use std::path::Path;
    use tempfile::tempdir;

    #[test]
    fn test_encrypt_snapshot() -> Result<(), Error> {
        let kp = KeyManagerBuilder::build_mock().unwrap();
        let epoch = 0;

        // Set up a temp dir
        let temp_dir = tempdir().unwrap();
        let temp_path = temp_dir.path();
        let snapshot_path = temp_path.join(SNAPSHOT_FILE);
        let ciphertext_path = temp_path.join(format!("{}.enc", SNAPSHOT_FILE));

        // Generate a dummy database file (e.g., 10MB)
        generate_dummy_file(&snapshot_path, 10 * 1024 * 1024)?;

        // Check the metadata of the original file
        let orig_leading_bytes =
            read_first_n_bytes(&snapshot_path.display().to_string(), 100).unwrap();

        // Create the encrypted snapshot
        encrypt_snapshot(
            &kp,
            epoch,
            temp_path.to_str().unwrap(),
            temp_path.to_str().unwrap(),
            SNAPSHOT_FILE,
        )
        .unwrap();
        assert!(Path::new(&ciphertext_path).exists());

        // Confirm that we recover the original file
        fs::remove_file(&snapshot_path)?;
        assert!(!Path::new(&snapshot_path).exists());
        decrypt_snapshot(
            &kp,
            epoch,
            temp_path.to_str().unwrap(),
            temp_path.to_str().unwrap(),
            SNAPSHOT_FILE,
        )
        .unwrap();
        assert!(Path::new(&snapshot_path).exists());

        // Check metadata of restored file matches the original
        let new_leading_bytes =
            read_first_n_bytes(&snapshot_path.display().to_string(), 100).unwrap();
        assert_eq!(orig_leading_bytes, new_leading_bytes);

        Ok(())
    }
}
