use std::path::Path;
use std::process::Command;
use std::fs;

use super::{RETH_DATA_DIR, SNAPSHOT_DIR};

/// Creates a snapshot by compressing the `mdbx.dat` file into a `.tar.lz4` archive.
/// Compressed file is saved in the same directory as the original file so that access permissions are identical
pub fn compress_datadir(
    data_dir: &str,
    snapshot_file: &str,
    mdbx_file: &str,
) -> Result<(), anyhow::Error> {
    fs::create_dir_all(SNAPSHOT_DIR).unwrap(); // TODO: error handling
    let snapshot_path = &format!("{}/{}", SNAPSHOT_DIR, snapshot_file);

    let exclude_items = [
        "discovery-secret",
        "invalid_block_hooks",
        "jwt.hex",
        "known-peers.json",
        "logs",
        "blobstore",
        snapshot_file, // prevent self-archiving by name
    ];

    let mut tar_args: Vec<String> = vec!["--use-compress-program=lz4".to_string()];
    // Exclude args
    for item in &exclude_items {
        tar_args.push("--exclude".to_string());
        tar_args.push(item.to_string());
    }
    tar_args.extend_from_slice(&[
        "-cvPf".to_string(),
        snapshot_path.clone(), // path for the output file
        ".".to_string(),       // (relative) path for what to compress
    ]);

    let output = Command::new("tar")
        .current_dir(data_dir) // run tar in the data_dir
        .args(&tar_args)
        .output()
        .expect("Failed to execute tar command");

    if !output.status.success() {
        anyhow::bail!("Failed to compress mdbx with tar: {:?}", output);
    }

    Ok(())
}

/// Restores the snapshot by extracting the `.tar.lz4` archive.
pub fn decompress_datadir(data_dir: &str, snapshot_file: &str) -> Result<(), anyhow::Error> {
    let snapshot_path = format!("{}/{}", SNAPSHOT_DIR, snapshot_file);

    // Confirm that the snapshot file exists
    if !Path::new(&snapshot_path).exists() {
        anyhow::bail!(
            "Snapshot file not found at expected path: {}",
            snapshot_path
        );
    }

    // Run the tar command to decompress the snapshot
    let output = Command::new("tar")
        .current_dir(data_dir)
        .args(["--use-compress-program=lz4", "-xvPf", &snapshot_path])
        .output()
        .expect("Failed to execute tar command");

    if !output.status.success() {
        anyhow::bail!(
            "Failed to decompress snapshot with tar: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::{MDBX_FILE, SNAPSHOT_FILE};
    use crate::utils::test_utils::{
        generate_dummy_file, read_first_n_bytes,
    };

    use std::fs;
    use std::path::Path;
    use tempfile::tempdir;


    // TODO: make a second temp dir instead of SNAPSHOT_DIR
    // TODO: check that appropriate files are excluded, included
    #[test]
    fn test_compress_datadir() -> Result<(), anyhow::Error> {
        // Set up a temp dir
        println!("Current dir: {:?}", std::env::current_dir().unwrap());
        let temp_dir = tempdir().unwrap();
        let temp_path = temp_dir.path();
        fs::create_dir(temp_path.join("db"))?;
        let snapshot_path = &format!("{}/{}", SNAPSHOT_DIR, SNAPSHOT_FILE); 
        let mdbx_path = temp_path.join("db").join(MDBX_FILE);

        // Generate a dummy database file (e.g., 10MB)
        generate_dummy_file(&mdbx_path, 10 * 1024 * 1024)?;
        // Check the metadata of the original file
        let orig_leading_bytes = read_first_n_bytes(&mdbx_path.display().to_string(), 100).unwrap();

        // Create the snapshot
        compress_datadir(temp_dir.path().to_str().unwrap(), SNAPSHOT_FILE, MDBX_FILE).unwrap();
        assert!(Path::new(&snapshot_path).exists());

        // Confirm that we recover the original file
        fs::remove_file(&mdbx_path)?;
        assert!(!Path::new(&mdbx_path).exists());
        decompress_datadir(temp_dir.path().to_str().unwrap(), SNAPSHOT_FILE).unwrap();
        assert!(Path::new(&mdbx_path).exists());

        // Check metadata of restored file matches the original
        let new_leading_bytes = read_first_n_bytes(&mdbx_path.display().to_string(), 100).unwrap();
        assert_eq!(orig_leading_bytes, new_leading_bytes);

        Ok(())
    }
}
