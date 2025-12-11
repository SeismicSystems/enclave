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

        // Summit will write the epoch number over the socket first thing
        // epoch is u64
        let mut buffer = [0u8; 32];
        let epoch = match stream.read(&mut buffer).await {
            Ok(n) if n > 0 => {
                let epoch_str = String::from_utf8_lossy(&buffer[..n]).trim().to_string();

                match epoch_str.parse::<u64>() {
                    Ok(id) => {
                        info!("Received backup ID: {}", id);
                        id
                    }
                    Err(e) => {
                        error!("Invalid u64 received for epoch over summit socket: {}", e);
                        if let Err(e) = stream.write_all(b"ERROR: Invalid epoch format\n").await {
                            error!("Failed to send error response: {}", e);
                        }
                        continue;
                    }
                }
            }
            Ok(_) => {
                error!("Empty message received");
                if let Err(e) = stream.write_all(b"ERROR: Empty message\n").await {
                    error!("Failed to send error response: {}", e);
                }
                continue;
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
        if let Err(e) = stream.write_all(b"OK\n").await {
            error!("Failed to send acknowledgment: {}", e);
            continue;
        }

        // Now read the checkpoint data
        // Read all available bytes from the stream
        let mut checkpoint_data = Vec::new();
        match stream.read_to_end(&mut checkpoint_data).await {
            Ok(n) => {
                info!(
                    "Received {} bytes of checkpoint data for epoch {}",
                    n, epoch
                );

                // Process the checkpoint data here
                // For example:
                // if let Err(e) = process_checkpoint(epoch, &checkpoint_data, &key_manager).await {
                //     error!("Failed to process checkpoint: {}", e);
                //     continue;
                // }

                info!("Successfully processed checkpoint for epoch {}", epoch);
            }
            Err(e) => {
                error!("Failed to read checkpoint data: {}", e);
                continue;
            }
        }

        // Copy the database and prepare for it to be encrypted
        let response = match prepare_encrypted_snapshot(epoch, checkpoint_data).await {
            Ok(_) => "SUCCESS\n",
            Err(e) => {
                error!("Backup failed: {}", e);
                "FAILURE\n"
            }
        };

        // Let summit know that it can continue and reth is restarted
        if let Err(e) = stream.write_all(response.as_bytes()).await {
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
