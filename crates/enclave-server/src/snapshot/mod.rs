mod check_operator;
mod compress;
mod file_encrypt;
pub mod handlers;
pub use check_operator::check_operator;
use compress::{compress_datadir, decompress_datadir};
use file_encrypt::{decrypt_snapshot, encrypt_snapshot}; // re-export for integration testing

use crate::key_manager::NetworkKeyProvider;
#[cfg(not(feature = "supervisorctl"))]
use crate::utils::service::{start_reth, stop_reth};
#[cfg(feature = "supervisorctl")]
use crate::utils::supervisorctl::{start_reth, stop_reth};

use std::fs;

pub const DATA_DISK_DIR: &str = "/mnt/datadisk";
// pub const RETH_DATA_DIR: &str = "/home/azureuser/.reth"; // correct when running reth with `cargo run` on devbox
pub const RETH_DATA_DIR: &str = "/persistent/reth"; // correct when running with yocto builds
pub const SNAPSHOT_DIR: &str = "/tmp/snapshot";
pub const SNAPSHOT_FILE: &str = "seismic_reth_snapshot.tar.lz4";

/// Prepares an encrypted snapshot of the Reth database and stores it on a mounted data disk.
///
/// This function performs the following steps:
/// 1. Stops the Reth process to ensure the database is in a consistent state.
/// 2. Compresses the database directory into a snapshot archive.
/// 3. Encrypts the compressed snapshot using the snapshot key.
/// 4. Removes the temporary unencrypted snapshot archive.
/// 5. Restarts the Reth process after the snapshot is created.
///
/// After running this function, the encrypted snapshot is stored in a mounted data disk
/// (separate from the OS disk) for safe backup or transfer.
///
/// # Arguments
/// * `reth_data_dir` - Path to the Reth database directory.
/// * `data_disk_dir` - Path to the mounted data disk where the encrypted snapshot will be saved.
/// * `snapshot_dir` - Path to a temporary directory used to hold the unencrypted snapshot archive.
/// * `snapshot_file` - Filename of the snapshot archive (e.g., `snapshot.tar.lz4`).
///
/// # Errors
/// Returns an error if any step in the process (stopping Reth, compression, encryption,
/// removing temporary data, or restarting Reth) fails.
pub fn prepare_encrypted_snapshot(
   kp: &impl NetworkKeyProvider,
   reth_data_dir: &str,
   data_disk_dir: &str,
   snapshot_dir: &str,
   snapshot_file: &str,
) -> Result<(), anyhow::Error> {
   fs::create_dir_all(snapshot_dir)
       .map_err(|e| anyhow::anyhow!("Failed to create snapshot directory: {:?}", e))?;
   stop_reth()?;
   compress_datadir(reth_data_dir, snapshot_dir, snapshot_file)?;
   encrypt_snapshot(kp, snapshot_dir, data_disk_dir, snapshot_file)?;
   fs::remove_dir_all(snapshot_dir)
       .map_err(|e| anyhow::anyhow!("Failed to remove snapshot directory: {:?}", e))?;
   start_reth()?;
   Ok(())
}

/// Restores the Reth database from an encrypted snapshot stored on a mounted data disk.
///
/// This function performs the following steps:
/// 1. Stops the Reth process to allow safe restoration.
/// 2. Decrypts the encrypted snapshot archive using the snapshot key.
/// 3. Decompresses the decrypted archive into the database directory.
/// 4. Removes the temporary snapshot data after restoration.
/// 5. Restarts the Reth process with the restored database state.
///
/// The encrypted snapshot must be available on the mounted data disk before calling this function.
///
/// # Arguments
/// * `reth_data_dir` - Path to the Reth database directory where the snapshot will be restored.
/// * `data_disk_dir` - Path to the mounted data disk where the encrypted snapshot archive is located.
/// * `snapshot_dir` - Temporary directory used during the decryption and decompression steps.
/// * `snapshot_file` - Filename of the snapshot archive (e.g., `snapshot.tar.lz4`).
///
/// # Errors
/// Returns an error if any step in the process (stopping Reth, decryption, decompression,
/// removing temporary data, or restarting Reth) fails.
pub fn restore_from_encrypted_snapshot(
   kp: &impl NetworkKeyProvider,
   reth_data_dir: &str,
   data_disk_dir: &str,
   snapshot_dir: &str,
   snapshot_file: &str,
) -> Result<(), anyhow::Error> {
   fs::create_dir_all(snapshot_dir)
       .map_err(|e| anyhow::anyhow!("Failed to create snapshot directory: {:?}", e))?;
   stop_reth()?;
   decrypt_snapshot(kp, data_disk_dir, snapshot_dir, snapshot_file)?;
   decompress_datadir(reth_data_dir, snapshot_dir, snapshot_file)?;
   fs::remove_dir_all(snapshot_dir)
       .map_err(|e| anyhow::anyhow!("Failed to remove snapshot directory: {:?}", e))?;
   start_reth()?;
   Ok(())
}
