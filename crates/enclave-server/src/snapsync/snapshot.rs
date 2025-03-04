use std::path::Path;
use std::process::Command;

// Constants for paths

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

// todo: some kind of error checking, ex if file is missing, restrictive permissions, etc
// todo: put an integation test somewhere that uses actual reth?
// todo: test that it overwrites the file if it already exists?
#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapsync::{MDBX_FILE, SNAPSHOT_FILE};
    use std::fs;
    use anyhow::Error;
    use std::io::Write;
    use std::path::Path;
    use tempfile::tempdir;

    fn file_metadata(file_path: &Path) -> Option<(u64, u64)> {
        let metadata = fs::metadata(file_path).ok()?;
        let file_size = metadata.len();
        let modified_time = metadata
            .modified()
            .ok()?
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs();
        Some((file_size, modified_time))
    }

    // Function to generate a dummy database file
    fn generate_dummy_file(path: &Path, size: usize) -> std::io::Result<()> {
        let mut file = fs::File::create(path)?;
        file.write_all(&vec![0u8; size])?; // Fill with zero bytes
        Ok(())
    }

    #[test]
    fn test_create_snapshot() -> Result<(), Error> {
        // Set up a temp dir
        println!("Current dir: {:?}", std::env::current_dir().unwrap());
        let temp_dir = tempdir().unwrap();
        let temp_path = temp_dir.path();
        let snapshot_path = temp_path.join(SNAPSHOT_FILE);
        let mdbx_path = temp_path.join(MDBX_FILE);

        // Generate a dummy database file (e.g., 10MB)
        generate_dummy_file(&mdbx_path, 10 * 1024 * 1024)?;

        // Check the metadata of the original file
        let orig_metadata = file_metadata(&mdbx_path).unwrap();

        // Create the snapshot
        create_snapshot(temp_dir.path().to_str().unwrap(), SNAPSHOT_FILE, MDBX_FILE).unwrap();
        assert!(Path::new(&snapshot_path).exists());

        // Confirm that we recover the original file
        fs::remove_file(&mdbx_path)?;
        assert!(!Path::new(&mdbx_path).exists());
        restore_snapshot(temp_dir.path().to_str().unwrap(), SNAPSHOT_FILE).unwrap();
        assert!(Path::new(&mdbx_path).exists());

        // Check metadata of restored file matches the original
        let new_metadata = file_metadata(&mdbx_path).unwrap();
        assert_eq!(orig_metadata.0, new_metadata.0);
        assert_eq!(orig_metadata.1, new_metadata.1);

        Ok(())
    }
}
