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

#[cfg(test)]
mod tests {
    use crate::snapsync::{RETH_DB_DIR, SNAPSHOT_FILE, MDBX_FILE};
    use super::*;

    // todo: refactor to use a temp dir
    // todo: some kind of file integrity check with sha256
    // todo: some kind of error checking, ex if file is missing, restrictive permissions, etc
    // todo: put an integation test somewhere that uses actual reth?

    #[test]
    fn test_create_snapshot() {
        let snapshot_path = &format!("{}/{}", RETH_DB_DIR, SNAPSHOT_FILE);
        let mdbx_path = &format!("{}/{}", RETH_DB_DIR, MDBX_FILE);
        if !Path::new(&mdbx_path).exists() {
            panic!("Database file not found at expected path: {:?}", &mdbx_path);
        }
        create_snapshot(RETH_DB_DIR, SNAPSHOT_FILE, MDBX_FILE).unwrap();
        assert!(Path::new(&snapshot_path).exists());
    }

    #[test]
    fn test_restore_snapshot() {
        let snapshot_path = &format!("{}/{}", RETH_DB_DIR, SNAPSHOT_FILE);
        let mdbx_path = &format!("{}/{}", RETH_DB_DIR, MDBX_FILE);
        if !Path::new(&snapshot_path).exists() {
            panic!(
                "Snapshot file not found at expected path: {:?}",
                &snapshot_path
            );
        }
        restore_snapshot(RETH_DB_DIR, SNAPSHOT_FILE).unwrap();
        assert!(Path::new(mdbx_path).exists());
    }
}
