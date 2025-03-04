use std::path::Path;
use std::process::Command;

// Constants for paths
const DB_DIR: &str = "/home/azureuser/.local/share/reth/5124/db";
const SNAPSHOT_FILE: &str = "seismic_reth_snapshot.tar.lz4";
const MDBX_FILE: &str = "mdbx.dat";

/// Creates a snapshot by compressing the `mdbx.dat` file into a `.tar.lz4` archive.
fn create_snapshot() -> Result<(), anyhow::Error> {
    let snapshot_path = &format!("{}/{}", DB_DIR, SNAPSHOT_FILE);
    let mdbx_path = &format!("{}/{}", DB_DIR, MDBX_FILE);

    // confirm that the mdbx file exists
    if !Path::new(&mdbx_path).exists() {
        anyhow::bail!("Database file not found at expected path: {:?}", &mdbx_path);
    }

    // run the tar command to create the compressed snapshot
    let status = Command::new("sudo")
        .args([
            "tar",
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
fn restore_snapshot() -> Result<(), anyhow::Error> {
    let snapshot_path = &format!("{}/{}", DB_DIR, SNAPSHOT_FILE);

    // confirm that the snapshot file exists
    if !Path::new(&snapshot_path).exists() {
        anyhow::bail!("Snapshot file not found at expected path: {:?}", &snapshot_path);
    }

    // run the tar command to decompress the snapshot
    let status = Command::new("sudo")
    .args([
        "tar",
        "--use-compress-program=lz4",
        "-xvPf",
        &snapshot_path,
    ])
    .status()
    .expect("Failed to execute tar command");

    if !status.success() {
        anyhow::bail!("Failed to decompress snapshot with tar");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_snapshot() {
        let snapshot_path = &format!("{}/{}", DB_DIR, SNAPSHOT_FILE);
        let mdbx_path = &format!("{}/{}", DB_DIR, MDBX_FILE);
        if !Path::new(&mdbx_path).exists() {
            panic!("Database file not found at expected path: {:?}", &mdbx_path);
        }
        create_snapshot().unwrap();
        assert!(Path::new(&snapshot_path).exists());
    }

    #[test]
    fn test_restore_snapshot() {
        let snapshot_path = &format!("{}/{}", DB_DIR, SNAPSHOT_FILE);
        let mdbx_path = &format!("{}/{}", DB_DIR, MDBX_FILE);
        if !Path::new(&snapshot_path).exists() {
            panic!("Snapshot file not found at expected path: {:?}", &snapshot_path);
        }
        restore_snapshot().unwrap();
        assert!(Path::new(mdbx_path).exists());
    }
}
