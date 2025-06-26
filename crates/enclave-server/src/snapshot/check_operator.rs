use alloy::{primitives::{address, Address, Bytes}, providers::ProviderBuilder, sol};
use std::sync::Arc;
use anyhow::Result;

// Contract address
const OPERATOR_ADDR: Address = address!("0x5FbDB2315678afecb367f032d93F642f64180aa3");

// Generate contract bindings inline with RPC support
sol! {
    #[sol(rpc)]
    interface UpgradeOperator {
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
    let provider = ProviderBuilder::new().connect_http("http://localhost:8545".parse()?);

    // Instantiate the contract

    // Call the `get_mrtd` function
    let contract = UpgradeOperator::new(OPERATOR_ADDR, Arc::new(provider));
    let builder = contract.get_mrtd(rootfs_hash, mrtd, rtmr0, rtmr3);
    let is_valid = builder.call().await?;

    Ok(is_valid)
}
