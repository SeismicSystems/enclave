mod check_operator;
mod compress;
mod file_encrypt;
pub mod handlers;

use crate::utils::supervisor::{start_reth, stop_reth};
pub use check_operator::check_operator;
use compress::{compress_datadir, decompress_datadir};
use file_encrypt::{decrypt_snapshot, encrypt_snapshot}; // re-export for e2e testing

use std::fs;

pub const DATA_DISK_DIR: &str = "/mnt/datadisk";
pub const RETH_DATA_DIR: &str = "/home/azureuser/.reth"; // correct when running reth with `cargo run`
pub const SNAPSHOT_DIR: &str = "/tmp/snapshot";
pub const SNAPSHOT_FILE: &str = "seismic_reth_snapshot.tar.lz4";

/// Prepares an encrypted snapshot of the Reth database for download.
///
/// This function performs the following steps:
/// 1. Stops the Reth process to ensure the database is in a consistent state.
/// 2. Compresses the database directory into a snapshot archive.
/// 3. Encrypts the compressed snapshot.
/// 4. Restarts the Reth process after the snapshot is created.
///
/// After running this function, the encrypted snapshot file can be served via a download endpoint.
///
/// # Arguments
/// * `db_dir` - Path to the Reth database directory.
/// * `snapshot_file` - Path to the final snapshot archive (will be created or overwritten).
/// * `mdbx_file` - Path to the MDBX data file used during compression.
///
/// # Errors
/// Returns an error if any step in the process (stopping Reth, compression, encryption, or restarting Reth) fails.
pub fn prepare_encrypted_snapshot(
    reth_data_dir: &str,
    data_disk_dir: &str,
    snapshot_dir: &str,
    snapshot_file: &str,
) -> Result<(), anyhow::Error> {
    fs::create_dir_all(snapshot_dir).map_err(
        |e| anyhow::anyhow!("Failed to create snapshot directory: {:?}", e),
    )?;
    stop_reth().expect("Failed to stop reth during create_encrypted_snapshot");
    compress_datadir(reth_data_dir, snapshot_dir, snapshot_file)?;
    encrypt_snapshot(snapshot_dir, data_disk_dir, snapshot_file)?;
    fs::remove_dir_all(snapshot_dir).map_err(
        |e| anyhow::anyhow!("Failed to remove snapshot directory: {:?}", e),
    )?;
    start_reth().expect("Failed to start reth during create_encrypted_snapshot");
    Ok(())
}

/// Restores the Reth database from an encrypted snapshot archive.
///
/// This function performs the following steps:
/// 1. Stops the Reth process to allow safe restoration.
/// 2. Decrypts the uploaded snapshot archive.
/// 3. Decompresses the decrypted archive into the database directory.
/// 4. Restarts the Reth process once the database has been restored.
///
/// The encrypted snapshot must be uploaded via the relevant endpoint before calling this function.
///
/// # Arguments
/// * `db_dir` - Path to the Reth database directory where the snapshot will be restored.
/// * `snapshot_file` - Path to the encrypted snapshot archive.
///
/// # Errors
/// Returns an error if any step in the process (stopping Reth, decryption, decompression, or restarting Reth) fails.
pub fn restore_from_encrypted_snapshot(
    reth_data_dir: &str,
    data_disk_dir: &str,
    snapshot_dir: &str,
    snapshot_file: &str,
) -> Result<(), anyhow::Error> {
    fs::create_dir_all(snapshot_dir).map_err(
        |e| anyhow::anyhow!("Failed to create snapshot directory: {:?}", e),
    )?;
    stop_reth()?;
    decrypt_snapshot(data_disk_dir, snapshot_dir, snapshot_file)?;
    decompress_datadir(reth_data_dir, snapshot_dir, snapshot_file)?;
    fs::remove_dir_all(snapshot_dir).map_err(
        |e| anyhow::anyhow!("Failed to remove snapshot directory: {:?}", e),
    )?;
    start_reth()?;
    Ok(())
}
