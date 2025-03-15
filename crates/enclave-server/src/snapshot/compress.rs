use std::path::Path;
use std::process::Command;

/// Compresses the contents of a data directory (`data_dir`) into a `.tar.lz4` snapshot archive.
///
/// The archive is created using the `tar` command with LZ4 compression and stored in the
/// `snapshot_dir` with the given `snapshot_file` name. Certain files and directories are
/// excluded from the archive, such as reth networking secrets
///
/// # Arguments
///
/// * `data_dir` - Path to the data directory containing the MDBX database, static_files, and other runtime files.
/// * `snapshot_dir` - Path to the directory where the snapshot archive should be saved.
/// * `snapshot_file` - Filename for the resulting `.tar.lz4` archive (e.g., `snapshot.tar.lz4`).
///
/// # Returns
///
/// Returns `Ok(())` if the compression succeeds, or an `anyhow::Error` if the `tar` command fails.
///
/// # Errors
///
/// This function returns an error if the `tar` command fails to execute or exits with a non-zero status.
pub fn compress_datadir(
    data_dir: &str,
    snapshot_dir: &str,
    snapshot_file: &str,
) -> Result<(), anyhow::Error> {
    let snapshot_path = &format!("{}/{}", snapshot_dir, snapshot_file);

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
        .map_err(|e| anyhow::anyhow!("Failed to decompress snapshot with tar: {:?}", e))?;

    if !output.status.success() {
        anyhow::bail!("Failed to compress datadir with tar:\n {:?}", output);
    }

    Ok(())
}

/// Decompresses a `.tar.lz4` snapshot archive into a specified data directory (`data_dir`).
///
/// This function restores the contents of a previously created snapshot archive by extracting
/// its contents using the `tar` command with LZ4 decompression. It is commonly used for
/// restoring database state from a backup or test snapshot.
///
/// # Arguments
///
/// * `data_dir` - Path to the directory where the archive should be extracted.
/// * `snapshot_dir` - Path to the directory where the snapshot archive is stored.
/// * `snapshot_file` - Filename of the `.tar.lz4` snapshot archive to restore (e.g., `snapshot.tar.lz4`).
///
/// # Returns
///
/// Returns `Ok(())` if the decompression succeeds, or an `anyhow::Error` if the file is missing or extraction fails.
///
/// # Errors
///
/// This function returns an error if:
/// - The snapshot file does not exist at the specified path.
/// - The `tar` command fails to execute or returns a non-zero exit status.
pub fn decompress_datadir(
    data_dir: &str,
    snapshot_dir: &str,
    snapshot_file: &str,
) -> Result<(), anyhow::Error> {
    let snapshot_path = format!("{}/{}", snapshot_dir, snapshot_file);

    // Confirm that the snapshot file exists
    if !Path::new(&snapshot_path).exists() {
        anyhow::bail!(
            "Snapshot file not found at expected path: {}",
            snapshot_path
        );
    }

    // change the umask so that files can be written to by the user's group
    // so that reth can write to the files
    Command::new("umask")
        .current_dir(data_dir)
        .args(["0002"])
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to change umask to 0002: {:?}", e))?;

    // Run the tar command to decompress the snapshot
    let output = Command::new("tar")
    .current_dir(data_dir)
    .args([
        "--use-compress-program=lz4",
        "--no-same-permissions",
        "--no-same-owner",
        "-xvPf",
        &snapshot_path,
    ])
    .output()
    .map_err(|e| anyhow::anyhow!("Failed to spwan tar process: {:?}", e))?;

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
    
        return Err(anyhow::anyhow!(
            "tar extraction failed.\nExit code: {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            stdout,
            stderr,
        ));
    }

    // change the umask back
    Command::new("umask")
        .current_dir(data_dir)
        .args(["0022"])
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to change umask back to 0022: {:?}", e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::SNAPSHOT_FILE;
    use crate::utils::test_utils::{generate_dummy_file, read_first_n_bytes};

    use std::fs;
    use std::path::Path;
    use tempfile::tempdir;

    #[test]
    fn test_compress_datadir() -> Result<(), anyhow::Error> {
        // Set up a temp dir
        let temp_data_dir = tempdir().unwrap();
        let temp_data_dir_path = temp_data_dir.path();
        let temp_snapshot_dir = tempdir().unwrap();
        fs::create_dir(temp_data_dir_path.join("db"))?;
        let snapshot_path = &format!(
            "{}/{}",
            temp_snapshot_dir.path().to_str().unwrap(),
            SNAPSHOT_FILE
        );
        let mdbx_path = temp_data_dir_path.join("db").join("mdbx.dat");

        // Generate a dummy database file (e.g., 10MB)
        generate_dummy_file(&mdbx_path, 10 * 1024 * 1024)?;
        // Check the metadata of the original file
        let orig_leading_bytes = read_first_n_bytes(&mdbx_path.display().to_string(), 100).unwrap();

        // Create the snapshot
        compress_datadir(
            temp_data_dir.path().to_str().unwrap(),
            temp_snapshot_dir.path().to_str().unwrap(),
            SNAPSHOT_FILE,
        )
        .unwrap();
        assert!(Path::new(&snapshot_path).exists());

        // Confirm that we recover the original file
        fs::remove_file(&mdbx_path)?;
        assert!(!Path::new(&mdbx_path).exists());
        decompress_datadir(
            temp_data_dir.path().to_str().unwrap(),
            temp_snapshot_dir.path().to_str().unwrap(),
            SNAPSHOT_FILE,
        )
        .unwrap();
        assert!(Path::new(&mdbx_path).exists());

        // Check metadata of restored file matches the original
        let new_leading_bytes = read_first_n_bytes(&mdbx_path.display().to_string(), 100).unwrap();
        assert_eq!(orig_leading_bytes, new_leading_bytes);

        Ok(())
    }
}
