use crate::get_snapshot_key;

use std::path::Path;
use std::process::Command;
use seismic_enclave::crypto::{encrypt_file, decrypt_file};

// fn create_encrypted_snapshot(db_dir: &str, snapshot_file: &str, mdbx_file: &str) -> Result<(), anyhow::Error> {
//     create_snapshot(db_dir, snapshot_file, mdbx_file);
//     encrypt_snapshot(db_dir, snapshot_file);
//     Ok(())
// }

/// Creates a snapshot by compressing the `mdbx.dat` file into a `.tar.lz4` archive.
fn create_snapshot(
    db_dir: &str,
    snapshot_file: &str,
    mdbx_file: &str,
) -> Result<(), anyhow::Error> {
    let snapshot_path = &format!("{}/{}", db_dir, snapshot_file);
    let mdbx_path = &format!("{}/{}", db_dir, mdbx_file);

    // confirm that the mdbx file exists
    if !Path::new(&mdbx_path).exists() {
        anyhow::bail!("Database file not found at expected path: {:?}", &mdbx_path);
    }

    // run the tar command to create the compressed snapshot
    let status = Command::new("tar")
        .args([
            "--use-compress-program=lz4",
            "-cvPf",
            snapshot_path,
            mdbx_path,
        ])
        .status()
        .expect("Failed to execute tar command");

    if !status.success() {
        anyhow::bail!("Failed to compress mdbx with tar");
    }

    Ok(())
}

/// Restores the snapshot by extracting the `.tar.lz4` archive.
fn restore_snapshot(db_dir: &str, snapshot_file: &str) -> Result<(), anyhow::Error> {
    let snapshot_path = &format!("{}/{}", db_dir, snapshot_file);

    // confirm that the snapshot file exists
    if !Path::new(&snapshot_path).exists() {
        anyhow::bail!(
            "Snapshot file not found at expected path: {:?}",
            &snapshot_path
        );
    }

    // run the tar command to decompress the snapshot
    let status = Command::new("tar")
        .args(["--use-compress-program=lz4", "-xvPf", &snapshot_path])
        .status()
        .expect("Failed to execute tar command");

    if !status.success() {
        anyhow::bail!("Failed to decompress snapshot with tar");
    }

    Ok(())
}

/// Encrypts the snapshot file using the snapshot_key
fn encrypt_snapshot(db_dir: &str, snapshot_file: &str) -> Result<(), anyhow::Error> {
    let snapshot_path = &format!("{}/{}", db_dir, snapshot_file);
    let ciphertext_path = &format!("{}.enc", snapshot_path);

    // confirm that the snapshot file exists
    if !Path::new(&snapshot_path).exists() {
        anyhow::bail!(
            "Snapshot file not found at expected path: {:?}",
            &snapshot_path
        );
    }

    let snapshot_key = get_snapshot_key();
    encrypt_file(&snapshot_path, &ciphertext_path, &snapshot_key)?;

    Ok(())
}

/// Decrypts the snapshot file using the snapshot_key
fn decrypt_snapshot(db_dir: &str, snapshot_file: &str) -> Result<(), anyhow::Error> {
    let snapshot_path = &format!("{}/{}", db_dir, snapshot_file);
    let ciphertext_path = &format!("{}.enc", snapshot_path);

    // confirm that the snapshot file exists
    if !Path::new(&ciphertext_path).exists() {
        anyhow::bail!(
            "Encrypted Snapshot file not found at expected path: {:?}",
            &snapshot_path
        );
    }

    let snapshot_key = get_snapshot_key();
    decrypt_file(&ciphertext_path, &snapshot_path, &snapshot_key)?;

    Ok(())
}

// todo: some kind of error checking, ex if file is missing, restrictive permissions, etc
// todo: put an integation test somewhere that uses actual reth?
// todo: test that it overwrites the file if it already exists?
#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapsync::{MDBX_FILE, SNAPSHOT_FILE};
    use std::fs;
    use anyhow::Error;
    use std::io::{Read, Write};
    use std::path::Path;
    use tempfile::tempdir;

    fn read_first_n_bytes(file_path: &str, n: usize) -> Result<Vec<u8>, anyhow::Error>{
        let mut file = fs::File::open(file_path)?;
        let mut buffer = vec![0; n]; // Allocate a buffer of size `n`
        let bytes_read = file.read(&mut buffer)?;
    
        buffer.truncate(bytes_read); // Truncate buffer in case file is smaller than `n`
        Ok(buffer)
    }

    // Function to generate a dummy database file
    fn generate_dummy_file(path: &Path, size: usize) -> std::io::Result<()> {
        let mut file = fs::File::create(path)?;
        file.write_all(&vec![0u8; size])?; // Fill with zero bytes
        Ok(())
    }

    #[test]
    fn test_create_snapshot() -> Result<(), anyhow::Error> {
        // Set up a temp dir
        println!("Current dir: {:?}", std::env::current_dir().unwrap());
        let temp_dir = tempdir().unwrap();
        let temp_path = temp_dir.path();
        let snapshot_path = temp_path.join(SNAPSHOT_FILE);
        let mdbx_path = temp_path.join(MDBX_FILE);

        // Generate a dummy database file (e.g., 10MB)
        generate_dummy_file(&mdbx_path, 10 * 1024 * 1024)?;

        // Check the metadata of the original file
        let orig_leading_bytes = read_first_n_bytes(&mdbx_path.display().to_string(), 100).unwrap();

        // Create the snapshot
        create_snapshot(temp_dir.path().to_str().unwrap(), SNAPSHOT_FILE, MDBX_FILE).unwrap();
        assert!(Path::new(&snapshot_path).exists());

        // Confirm that we recover the original file
        fs::remove_file(&mdbx_path)?;
        assert!(!Path::new(&mdbx_path).exists());
        restore_snapshot(temp_dir.path().to_str().unwrap(), SNAPSHOT_FILE).unwrap();
        assert!(Path::new(&mdbx_path).exists());

        // Check metadata of restored file matches the original
        let new_leading_bytes = read_first_n_bytes(&mdbx_path.display().to_string(), 100).unwrap();
        assert_eq!(orig_leading_bytes, new_leading_bytes);

        Ok(())
    }

    #[test]
    fn test_encrypt_snapshot() -> Result<(), Error> {
        // Set up a temp dir
        println!("Current dir: {:?}", std::env::current_dir().unwrap());
        let temp_dir = tempdir().unwrap();
        let temp_path = temp_dir.path();
        let snapshot_path = temp_path.join(SNAPSHOT_FILE);
        let ciphertext_path = temp_path.join(format!("{}.enc", SNAPSHOT_FILE));

        // Generate a dummy database file (e.g., 10MB)
        generate_dummy_file(&snapshot_path, 10 * 1024 * 1024)?;

        // Check the metadata of the original file
        let orig_leading_bytes = read_first_n_bytes(&snapshot_path.display().to_string(), 100).unwrap();

        // Create the encrypted snapshot
        encrypt_snapshot(temp_dir.path().to_str().unwrap(), SNAPSHOT_FILE).unwrap();
        assert!(Path::new(&ciphertext_path).exists());

        // Confirm that we recover the original file
        fs::remove_file(&snapshot_path)?;
        assert!(!Path::new(&snapshot_path).exists());
        decrypt_snapshot(temp_dir.path().to_str().unwrap(), SNAPSHOT_FILE).unwrap();
        assert!(Path::new(&snapshot_path).exists());

        // Check metadata of restored file matches the original
        let new_leading_bytes = read_first_n_bytes(&snapshot_path.display().to_string(), 100).unwrap();
        assert_eq!(orig_leading_bytes, new_leading_bytes);

        Ok(())
    }
}
