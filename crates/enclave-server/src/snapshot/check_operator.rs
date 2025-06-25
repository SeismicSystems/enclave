use alloy_primitives::{Address, Bytes};
use alloy_provider::ProviderBuilder;
use alloy_sol_types::sol;
use std::sync::Arc;

const OPERATOR_ADDR: &str = "0x5FbDB2315678afecb367f032d93F642f64180aa3"; // Future work: replace

// Define the Solidity ABI using the `sol!` macro
sol! {
    #[sol(rpc)]
    contract UpgradeOperator {
        function get_mrtd(bytes rootfs_hash, bytes mrtd, bytes rtmr0, bytes rtmr3) public view returns (bool);
    }
}

/// Checks if a specified configuration is an approved upgrade.
///
/// This function makes a view call to the `UpgradeOperator` contract on a local node
/// to invoke the `get_mrtd` function. The function evaluates whether the given configuration
/// has been registered as approved on-chain.
///
/// # Arguments
///
/// * `rootfs_hash` - A `Bytes` representation of the Root File System (RootFS) hash.
/// * `mrtd` - A `Bytes` representation of the measured runtime data (MRTD).
/// * `rtmr0` - A `Bytes` representation of the RTMR0 measurement register.
/// * `rtmr3` - A `Bytes` representation of the RTMR3 measurement register.
///
/// # Returns
///
/// * `Result<bool, anyhow::Error>` - Returns `Ok(true)` if the configuration is approved,
///   `Ok(false)` if it is not approved, or an `Err(anyhow::Error)` if an error occurs during
///   the contract call.
///
/// # Errors
///
/// This function returns an error if:
/// - The node at `http://localhost:8545` is unreachable.
/// - The `UpgradeOperator` contract call fails.
///
/// # Notes
///
/// - This function assumes that the `UpgradeOperator` contract is deployed at `OPERATOR_ADDR`.
/// - It connects to a **local** node running at `http://localhost:8545`.
/// - The function does **not** perform any state-changing operations on the blockchain.
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
    let is_valid: bool = result._0;

    Ok(is_valid)
}
