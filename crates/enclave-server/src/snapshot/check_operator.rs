use alloy::{primitives::{address, Address, Bytes}, providers::ProviderBuilder, sol};
use std::sync::Arc;
use anyhow::Result;

// Contract address
const OPERATOR_ADDR: Address = address!("0x5FbDB2315678afecb367f032d93F642f64180aa3");

// Generate contract bindings inline with RPC support
sol! {
    #[sol(rpc)]
    interface IUpgradeOperator {
        function get_mrtd(bytes rootfs_hash, bytes mrtd, bytes rtmr0, bytes rtmr3) external view returns (bool);
    }
}

/// Checks if a specified configuration is an approved upgrade.
///
/// This function makes a view call to the `UpgradeOperator` contract on a local node
/// to invoke the `get_mrtd` function. The function evaluates whether the given configuration
/// has been registered as approved on-chain.
pub async fn check_operator(
    rootfs_hash: Bytes,
    mrtd: Bytes,
    rtmr0: Bytes,
    rtmr3: Bytes,
) -> Result<bool, anyhow::Error> {
    // Set up the provider to connect to the local node
    let provider = ProviderBuilder::new().on_http("http://localhost:8545".parse()?);

    // Specify the contract address
    let contract_address: Address = OPERATOR_ADDR.parse().map_err(|e| {
        anyhow::anyhow!(
            "Unexpected Internal Error: Failed to parse UpgradeOperator contract address: {:?}",
            e
        )
    })?;

    // Instantiate the contract
    let contract = UpgradeOperator::new(contract_address, Arc::new(provider));

    // Call the `get_mrtd` function
    let result: UpgradeOperator::get_mrtdReturn = contract
        .get_mrtd(rootfs_hash, mrtd, rtmr0, rtmr3)
        .call()
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "Failed to call get_mrtd on UpgradeOperator contract: {:?}",
                e
            )
        })?;

    Ok(is_valid)
}
