//! Convenience functions for booting the enclave in a streamlined way
use std::net::IpAddr;
use std::time::Duration;

use crate::client::EnclaveClientBuilder;
use crate::request_types::GetPurposeKeysRequest;
use crate::rpc::EnclaveApiClient;

/// Errors that can occur when booting the enclave
#[derive(Debug, thiserror::Error)]
pub enum BootError {
    /// Error when the genesis boot fails
    #[error("Genesis boot failed: {0}")]
    GenesisFailed(String),
    /// Error when the complete boot fails
    #[error("Complete boot failed: {0}")]
    CompleteFailed(String),
    /// Error when getting the purpose keys fails
    #[error("Get purpose keys failed: {0}")]
    GetPurposeKeysFailed(String),
}

/// Command to boot the enclave's key manager
pub async fn boot_genesis_streamlined_async(ip: IpAddr, port: u16) -> Result<(), BootError> {
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
        tracing::error!("{}", e);
        return Err(BootError::GenesisFailed(e.to_string()));
    };

    if let Err(e) = client.complete_boot().await {
        tracing::error!("{}", e);
        return Err(BootError::CompleteFailed(e.to_string()));
    };

    if let Err(e) = client
        .get_purpose_keys(GetPurposeKeysRequest { epoch: 0 })
        .await
    {
        tracing::error!("{}", e);
        return Err(BootError::GetPurposeKeysFailed(e.to_string()));
    };

    Ok(())
}

/// Boot the enclave's key manager synchronously
pub fn boot_genesis_streamlined_sync(ip: IpAddr, port: u16) -> Result<(), BootError> {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(boot_genesis_streamlined_async(ip, port))?;
    Ok(())
}
