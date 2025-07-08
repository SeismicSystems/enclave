//! Convenience functions for booting the enclave in a streamlined way
use crate::EnclaveClient;
use crate::rpc::EnclaveApiClient;

/// Command to boot the enclave's key manager
pub async fn boot_genesis_streamlined_async(
    client: &EnclaveClient,
) -> Result<(), anyhow::Error> {
    let health_check = client.health_check().await?;
    if health_check.boot_complete {
        tracing::warn!("Enclave already booted. Skipping genesis boot");
        return Ok(());
    }
    client.boot_genesis().await?;
    client.complete_boot().await?;
    Ok(())
}

pub fn boot_genesis_streamlined_sync(
    client: &EnclaveClient,
) -> Result<(), anyhow::Error> {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(boot_genesis_streamlined_async(client))
}
