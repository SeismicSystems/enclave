use crate::get_snapshot_key;
use seismic_enclave::crypto::{decrypt_file, encrypt_file};

use std::path::Path;

/// Encrypts the snapshot file using the snapshot_key
pub fn encrypt_snapshot(input_dir: &str, output_dir: &str, snapshot_file: &str) -> Result<(), anyhow::Error> {
    let input_path = &format!("{}/{}", input_dir, snapshot_file);
    let output_path = &format!("{}/{}.enc", output_dir, snapshot_file);

    // confirm that the snapshot file exists
    if !Path::new(&input_path).exists() {
        anyhow::bail!(
            "Snapshot file not found at expected path: {:?}",
            &input_path
        );
    }

    let snapshot_key = get_snapshot_key();
    encrypt_file(&input_path, &output_path, &snapshot_key)
        .map_err(|e| anyhow::anyhow!("Failed to encrypt snapshot file: {:?}", e))?;

    Ok(())
}

/// Decrypts the snapshot file using the snapshot_key
pub fn decrypt_snapshot(input_dir: &str, output_dir: &str, snapshot_file: &str) -> Result<(), anyhow::Error> {
    let input_path = &format!("{}/{}.enc", input_dir, snapshot_file);
    let output_path = &format!("{}/{}", output_dir, snapshot_file);

    // confirm that the snapshot file exists
    if !Path::new(&input_path).exists() {
        anyhow::bail!(
            "Encrypted Snapshot file not found at expected path: {:?}",
            &input_path
        );
    }

    let snapshot_key = get_snapshot_key();
    decrypt_file(&input_path, &output_path, &snapshot_key)
        .map_err(|e| anyhow::anyhow!("Failed to decrypt snapshot file: {:?}", e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::SNAPSHOT_FILE;
    use crate::utils::test_utils::{generate_dummy_file, read_first_n_bytes};

    use anyhow::Error;
    use std::fs;
    use std::path::Path;
    use tempfile::tempdir;

    #[test]
    fn test_encrypt_snapshot() -> Result<(), Error> {
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
        encrypt_snapshot(temp_path.to_str().unwrap(), temp_path.to_str().unwrap(), SNAPSHOT_FILE).unwrap();
        assert!(Path::new(&ciphertext_path).exists());

        // Confirm that we recover the original file
        fs::remove_file(&snapshot_path)?;
        assert!(!Path::new(&snapshot_path).exists());
        decrypt_snapshot(temp_path.to_str().unwrap(), temp_path.to_str().unwrap(),SNAPSHOT_FILE).unwrap();
        assert!(Path::new(&snapshot_path).exists());

        // Check metadata of restored file matches the original
        let new_leading_bytes =
            read_first_n_bytes(&snapshot_path.display().to_string(), 100).unwrap();
        assert_eq!(orig_leading_bytes, new_leading_bytes);

        Ok(())
    }
}
