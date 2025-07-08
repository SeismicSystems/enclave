//! Convenience functions for booting the enclave in a streamlined way
use crate::rpc::SyncEnclaveApiClient;

/// Command to boot the enclave's key manager
pub async fn boot_genesis_streamlined(client: impl SyncEnclaveApiClient) -> Result<(), anyhow::Error> {
    let health_check = client.health_check()?;
    if health_check.boot_complete {
        tracing::warn!("Enclave already booted. Skipping genesis boot");
        return Ok(());
    }
    client.boot_genesis()?;
    client.complete_boot()?;
    Ok(())
}
