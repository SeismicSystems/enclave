
pub mod check_operator;
mod compress;
mod file_encrypt;

use crate::utils::supervisor::{start_reth, stop_reth};
use compress::{compress_db, decompress_db};
use file_encrypt::{decrypt_snapshot, encrypt_snapshot};


// pub const RETH_DB_DIR: &str = "/home/azureuser/.local/share/reth/5124/db"; // correct when running reth with `cargo run`
pub const RETH_DB_DIR: &str = "/home/azureuser/.reth/db"; // correct when running reth with supervisorctl
pub const SNAPSHOT_FILE: &str = "seismic_reth_snapshot.tar.lz4";
pub const MDBX_FILE: &str = "mdbx.dat";


pub fn create_encrypted_snapshot(db_dir: &str, snapshot_file: &str, mdbx_file: &str) -> Result<(), anyhow::Error> {
    stop_reth().expect("Failed to stop reth during create_encrypted_snapshot");
    compress_db(db_dir, snapshot_file, mdbx_file)?;
    encrypt_snapshot(db_dir, snapshot_file)?;
    start_reth().expect("Failed to start reth during create_encrypted_snapshot");
    Ok(())
}

pub fn restore_from_encrypted_snapshot(db_dir: &str, snapshot_file: &str) -> Result<(), anyhow::Error> {
    stop_reth()?;
    decrypt_snapshot(db_dir, snapshot_file)?;
    decompress_db(db_dir, snapshot_file)?;
    start_reth()?;
    Ok(())
}