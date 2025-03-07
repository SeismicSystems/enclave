use std::path::Path;
use std::process::Command;

/// Creates a snapshot by compressing the `mdbx.dat` file into a `.tar.lz4` archive.
pub fn compress_db(
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
    // we use command here because tar crate can only handle relative paths
    let output = Command::new("sudo")
        .args([
            "tar",
            "--use-compress-program=lz4",
            "-cvPf",
            snapshot_path,
            mdbx_path,
        ])
        .output()
        .expect("Failed to execute tar command");

    if !output.status.success() {
        anyhow::bail!("Failed to compress mdbx with tar: {:?}", output);
    }

    Ok(())
}

/// Restores the snapshot by extracting the `.tar.lz4` archive.
pub fn decompress_db(db_dir: &str, snapshot_file: &str) -> Result<(), anyhow::Error> {
    let snapshot_path = &format!("{}/{}", db_dir, snapshot_file);

    // confirm that the snapshot file exists
    if !Path::new(&snapshot_path).exists() {
        anyhow::bail!(
            "Snapshot file not found at expected path: {:?}",
            &snapshot_path
        );
    }

    // run the tar command to decompress the snapshot
    let output = Command::new("sudo")
        .args(["tar", "--use-compress-program=lz4", "-xvPf", &snapshot_path])
        .output()
        .expect("Failed to execute tar command");

    if !output.status.success() {
        anyhow::bail!("Failed to compress mdbx with tar: {:?}", output);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::{MDBX_FILE, SNAPSHOT_FILE};
    use crate::utils::test_utils::{
        generate_dummy_file, read_first_n_bytes, restrict_file_permissions,
        unrestrict_file_permissions,
    };

    use std::fs;
    use std::path::Path;
    use tempfile::tempdir;

    #[test]
    fn test_compress_db() -> Result<(), anyhow::Error> {
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
        // Restrict file permissions to 000 to simulate root ownership
        restrict_file_permissions(&mdbx_path)?;

        // Create the snapshot
        compress_db(temp_dir.path().to_str().unwrap(), SNAPSHOT_FILE, MDBX_FILE).unwrap();
        assert!(Path::new(&snapshot_path).exists());

        // Confirm that we recover the original file
        fs::remove_file(&mdbx_path)?;
        assert!(!Path::new(&mdbx_path).exists());
        decompress_db(temp_dir.path().to_str().unwrap(), SNAPSHOT_FILE).unwrap();
        assert!(Path::new(&mdbx_path).exists());

        // Check metadata of restored file matches the original
        unrestrict_file_permissions(&mdbx_path)?; // open permissions to read new leading bytes
        let new_leading_bytes = read_first_n_bytes(&mdbx_path.display().to_string(), 100).unwrap();
        assert_eq!(orig_leading_bytes, new_leading_bytes);

        Ok(())
    }
}
