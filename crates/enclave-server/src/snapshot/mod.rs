mod compress;
mod file_encrypt;

use crate::{
    key_manager::KeyManager,
    utils::{copy_dir_all, rename_or_copy, start_reth, start_summit, stop_reth, stop_summit},
};

use anyhow::Result;
use compress::compress_datadir;
pub use compress::decompress_datadir;
pub use file_encrypt::{decrypt_snapshot, encrypt_snapshot};
use std::{
    fs,
    path::{Path, PathBuf},
};

#[cfg(feature = "systemctl")]
pub const RETH_DATA_DIR: &str = "/persistent/reth"; // correct when running with Mkosi builds

#[cfg(not(feature = "systemctl"))]
pub const RETH_DATA_DIR: &str = "/home/azureuser/.reth"; // correct when running reth with `cargo run` on devbox

#[cfg(feature = "systemctl")]
pub const SUMMIT_DATA_DIR: &str = "/persistent/summit/db"; // correct when running with Mkosi builds

#[cfg(not(feature = "systemctl"))]
pub const SUMMIT_DATA_DIR: &str = "/home/azureuser/.summit/db"; // correct when running reth with `cargo run` on devbox

pub const DATA_DISK_DIR: &str = "/persistent/snapshots";
pub const SNAPSHOT_DIR: &str = "/tmp/snapshot";
pub const SNAPSHOT_FILE_PREFIX: &str = "seismic_reth_snapshot.tar.lz4";

/// Prepares an encrypted snapshot of the Reth database and stores it on a mounted data disk.
///
/// This function performs the following steps:
/// 1. Stops the Reth process to ensure the database is in a consistent state.
/// 2. Copies the database directory into a snapshot archive.
/// 3. Starts reth back up
/// 4. Places the summit checkpoint with the reth checkpoint
///
/// This function copies the reth db and prepares it for encryption. It is split into two steps so we can keep the amount of time reth is stopped to a minimum
/// After running this function, the encrypted snapshot is stored in a mounted data disk
/// (separate from the OS disk) for safe backup or transfer.
///
/// # Errors
/// Returns an error if any step in the process (stopping Reth, compression, encryption,
/// removing temporary data, or restarting Reth) fails.
pub async fn prepare_encrypted_snapshot(
    epoch: u64,
    summit_checkpoint: Vec<u8>,
) -> Result<(), anyhow::Error> {
    let destination = PathBuf::from(SNAPSHOT_DIR).join(format!("{}-snapshot", epoch));

    stop_reth().await?;
    copy_dir_all(RETH_DATA_DIR, destination.join("reth"))?;
    start_reth().await?;

    fs::write(destination.join("summit_checkpoint"), summit_checkpoint)?;

    Ok(())
}

/// Finished the encryption on a prepared snapshot. This is the final step of the process and reth will have been restarted by now
pub async fn finish_encrypted_snapshot(kp: &KeyManager, epoch: u64) -> Result<()> {
    let snapshot_file = format!("{SNAPSHOT_FILE_PREFIX}-{epoch}.tar.lz4");
    compress_datadir(
        &format!("{SNAPSHOT_DIR}/{epoch}-snapshot"),
        SNAPSHOT_DIR,
        &snapshot_file,
    )?;

    encrypt_snapshot(kp, SNAPSHOT_DIR, DATA_DISK_DIR, &snapshot_file)?;
    fs::remove_dir_all(SNAPSHOT_DIR)
        .map_err(|e| anyhow::anyhow!("Failed to remove snapshot directory: {:?}", e))?;
    Ok(())
}

/// Restores the Reth database from an encrypted snapshot stored on a mounted data disk.
///
/// This function performs the following steps:
/// 1. Stops the Reth/Summit process to allow safe restoration.
/// 2. Decrypts the encrypted snapshot archive using the snapshot key.
/// 3. Decompresses the decrypted archive into the database directory.
/// 4. Removes the temporary snapshot data after restoration.
/// 5. Restarts the Reth/Summit process with the restored database state.
///
/// The encrypted snapshot must be available on the mounted data disk before calling this function.
///
/// # Arguments
/// * `kp` - Path to the Reth database directory where the snapshot will be restored.
/// * `epoch` - Path to the mounted data disk where the encrypted snapshot archive is located.
/// * `encrypted_snapshot_path` - Path to the snapshot archive
///
/// # Errors
/// Returns an error if any step in the process (stopping Reth, decryption, decompression,
/// removing temporary data, or restarting Reth) fails.
pub async fn restore_from_encrypted_snapshot(
    kp: &KeyManager,
    epoch: u64,
    encrypted_snapshot_path: impl AsRef<Path>,
) -> Result<(), anyhow::Error> {
    fs::create_dir_all(SNAPSHOT_DIR)
        .map_err(|e| anyhow::anyhow!("Failed to create snapshot directory: {:?}", e))?;
    let compressed_path = format!("{SNAPSHOT_DIR}/{epoch}-snapshot.tar.lz4");
    let uncompressed_path = PathBuf::from(format!("{SNAPSHOT_DIR}/{epoch}-snapshot"));

    // Decrypt snapshot to temp folder
    decrypt_snapshot(kp, epoch, encrypted_snapshot_path, &compressed_path)?;
    // decompress snapshot into temp folder
    decompress_datadir(&uncompressed_path, compressed_path)?;

    // stop reth and summit
    stop_reth().await?;
    stop_summit().await?;

    // delete both databases
    std::fs::remove_dir_all(RETH_DATA_DIR)?;
    std::fs::remove_dir_all(SUMMIT_DATA_DIR)?;

    // move databases in proper location

    // Try to rename first (fastest method, works if on same filesystem)
    rename_or_copy(uncompressed_path.join("reth"), RETH_DATA_DIR)?;
    // start reth
    start_reth().await?;
    // mv summit checkpoint to proper path
    fs::create_dir_all(SUMMIT_DATA_DIR)
        .map_err(|e| anyhow::anyhow!("Failed to create snapshot directory: {:?}", e))?;
    rename_or_copy(
        uncompressed_path.join("summit_checkpoint"),
        format!("{SUMMIT_DATA_DIR}/checkpoint"),
    )?;
    // start summit
    start_summit().await?;

    fs::remove_dir_all(SNAPSHOT_DIR)
        .map_err(|e| anyhow::anyhow!("Failed to remove snapshot directory: {:?}", e))?;

    Ok(())
}
