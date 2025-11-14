use crate::error::{Result, TdxInitError};
use crate::utils::command::{execute_command_with_output, execute_command_with_stdin};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::path::PathBuf;
use tokio::fs;

type HmacSha256 = Hmac<Sha256>;

pub async fn compute_mac(passphrase: &str, header_file: &str) -> Result<Vec<u8>> {
    let header_data = fs::read(header_file).await?;
    let mut mac = HmacSha256::new_from_slice(passphrase.as_bytes())
        .map_err(|e| TdxInitError::LuksError(format!("HMAC key error: {}", e)))?;
    mac.update(&header_data);
    Ok(mac.finalize().into_bytes().to_vec())
}

pub async fn verify_mac(passphrase: &str, header_file: &str, expected_mac: &[u8]) -> Result<()> {
    let actual_mac = compute_mac(passphrase, header_file).await?;
    if actual_mac != expected_mac {
        return Err(TdxInitError::MacVerificationFailed);
    }
    Ok(())
}

pub async fn read_mac_from_device(device_path: &PathBuf) -> Result<Vec<u8>> {
    let mac_output = execute_command_with_output(
        "dd",
        &[
            &format!("if={}", device_path.to_str().unwrap()),
            "bs=512",
            "skip=32768",
            "count=1",
        ],
    )
    .await?;

    if mac_output.len() < 32 {
        return Err(TdxInitError::LuksError(
            "Incomplete MAC read from device".to_string(),
        ));
    }

    Ok(mac_output[..32].to_vec())
}

pub async fn write_mac_to_device(device_path: &PathBuf, mac: &[u8]) -> Result<()> {
    execute_command_with_stdin(
        "dd",
        &[
            &format!("of={}", device_path.to_str().unwrap()),
            "bs=512",
            "seek=32768",
            "count=1",
            "conv=notrunc",
        ],
        mac,
    )
    .await
}
