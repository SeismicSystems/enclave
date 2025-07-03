//! Boot the enclave's key manager
use std::net::IpAddr;
use std::time::Duration;

use seismic_enclave::client::EnclaveClientBuilder;
use seismic_enclave::rpc::EnclaveApiClient;


/// Errors that can occur when booting the enclave
#[derive(Debug)]
pub enum BootError {
    /// Error when the genesis boot fails
    GenesisFailed(String),
    /// Error when the complete boot fails
    CompleteFailed(String),
}

/// Command to boot the enclave's key manager
pub async fn boot_enclave(ip: IpAddr, port: u16) -> Result<(), BootError> {
    let client = EnclaveClientBuilder::new()
        .ip(ip.to_string())
        .port(port)
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    client.boot_genesis().await.map_err(|e| BootError::GenesisFailed(e.to_string()))?;
    client.complete_boot().await.map_err(|e| BootError::CompleteFailed(e.to_string()))?;
    Ok(())
}
