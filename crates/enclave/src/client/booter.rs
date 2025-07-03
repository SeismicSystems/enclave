//! Boot the enclave's key manager
use std::net::IpAddr;
use std::time::Duration;

use crate::client::EnclaveClientBuilder;
use crate::request_types::keys::GetPurposeKeysRequest;
use crate::rpc::EnclaveApiClient;

/// Errors that can occur when booting the enclave
#[derive(Debug)]
pub enum BootError {
    /// Error when the genesis boot fails
    GenesisFailed(String),
    /// Error when the complete boot fails
    CompleteFailed(String),
    /// Error when getting the purpose keys fails
    GetPurposeKeysFailed(String),
}

/// Command to boot the enclave's key manager
pub async fn boot_enclave(ip: IpAddr, port: u16) -> Result<(), BootError> {
    let client = EnclaveClientBuilder::new()
        .ip(ip.to_string())
        .port(port)
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    if let Ok(_) = client
        .get_purpose_keys(GetPurposeKeysRequest { epoch: 0 })
        .await
    {
        tracing::warn!("Enclave already booted. Skipping genesis boot.");
        return Ok(());
    };

    if let Err(e) = client.boot_genesis().await {
        tracing::error!("Genesis boot failed. Error:\n{}", e);
        return Err(BootError::GenesisFailed(e.to_string()));
    };

    if let Err(e) = client.complete_boot().await {
        tracing::error!("Complete boot failed. Error:\n{}", e);
        return Err(BootError::CompleteFailed(e.to_string()));
    };

    if let Err(e) = client
        .get_purpose_keys(GetPurposeKeysRequest { epoch: 0 })
        .await
    {
        tracing::error!("getPurposeKeys failed. Error:\n{}", e);
        return Err(BootError::GetPurposeKeysFailed(e.to_string()));
    };

    Ok(())
}
