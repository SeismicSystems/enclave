use anyhow::Result;
use std::fs;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::UnixListener,
};
use tracing::{error, info};

use crate::{
    key_manager::KeyManager,
    snapshot::{finish_encrypted_snapshot, prepare_encrypted_snapshot},
};

pub async fn run_summit_socket(socket_path: String, key_manager: KeyManager) -> Result<()> {
    let _ = fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path)?;
    info!("Bound to Summit->Enclave unix socket @ {socket_path}");

    while let Ok((mut stream, _)) = listener.accept().await {
        info!("Performing backup");

        // Read epoch number as u64 (8 bytes, little-endian)
        let mut epoch_bytes = [0u8; 8];
        let epoch = match stream.read_exact(&mut epoch_bytes).await {
            Ok(_) => {
                let epoch = u64::from_le_bytes(epoch_bytes);
                info!("Received backup ID: {}", epoch);
                epoch
            }
            Err(e) => {
                error!("Failed to read epoch over summit socket: {}", e);
                if let Err(e) = stream.write_all(b"ERROR: Failed to read epoch\n").await {
                    error!("Failed to send error response: {}", e);
                }
                continue;
            }
        };

        // Send acknowledgment that epoch was received
        if let Err(e) = stream.write_all(b"ACK").await {
            error!("Failed to send acknowledgment: {}", e);
            continue;
        }

        // Read the length of the checkpoint data (u32, 4 bytes, little-endian)
        let mut len_bytes = [0u8; 4];
        if let Err(e) = stream.read_exact(&mut len_bytes).await {
            error!("Failed to read checkpoint data length: {}", e);
            continue;
        }
        let data_len = u32::from_le_bytes(len_bytes) as usize;
        info!("Expecting {} bytes of checkpoint data", data_len);
        // Read the checkpoint data
        let mut checkpoint_data = vec![0u8; data_len];

        match stream.read_exact(&mut checkpoint_data).await {
            Ok(_) => {
                info!(
                    "Received {} bytes of checkpoint data for epoch {}",
                    data_len, epoch
                );
            }
            Err(e) => {
                error!("Failed to read checkpoint data: {}", e);
                continue;
            }
        }

        // Copy the database and prepare for it to be encrypted
        let response = match prepare_encrypted_snapshot(epoch, checkpoint_data).await {
            Ok(_) => b"ACK",
            Err(e) => {
                error!("Backup failed: {}", e);
                b"ACK"
            }
        };

        // Let summit know that it can continue and reth is restarted
        if let Err(e) = stream.write_all(response).await {
            error!("Failed to respond to Summit: {}", e);
        }

        // Finish the encryption
        if let Err(e) = finish_encrypted_snapshot(&key_manager, epoch).await {
            error!("Unable to finish encrypting snapshot for epoch {epoch}: {e}");
            // at this point there is not much more we can do Summit is already continuing we will have to wait until next time a snapshot is requested to try again
        }

        let _ = stream.flush().await;
    }

    Ok(())
}
