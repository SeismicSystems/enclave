use alloy_primitives::{Address, Bytes};
use alloy_provider::ProviderBuilder;
use alloy_sol_types::sol;
use std::sync::Arc;

const OPERATOR_ADDR: &str = "0x5FbDB2315678afecb367f032d93F642f64180aa3"; // TODO: replace

// Define the Solidity interface using the `sol!` macro
sol! {
    #[sol(rpc)]
    contract UpgradeOperator {
        function get_mrtd(bytes rootfs_hash, bytes mrtd, bytes rtmr0, bytes rtmr3) public view returns (bool);
    }
}

pub async fn check_operator(
    rootfs_hash: Bytes,
    mrtd: Bytes,
    rtmr0: Bytes,
    rtmr3: Bytes,
) -> Result<bool, anyhow::Error> {
    // Set up the provider to connect to the local Ethereum node
    let provider = ProviderBuilder::new().on_http("http://localhost:8545".parse()?);

    // Specify the contract address
    let contract_address: Address = OPERATOR_ADDR
        .parse()
        .expect("const OPERATOR_ADDR does not parse");

    // Instantiate the contract
    let contract = UpgradeOperator::new(contract_address, Arc::new(provider));

    // Call the `get_mrtd` function
    let result: UpgradeOperator::get_mrtdReturn = contract
        .get_mrtd(rootfs_hash, mrtd, rtmr0, rtmr3)
        .call()
        .await?;
    let is_valid: bool = result._0;

    // Output the result
    println!("get_mrtd result: {:?}", is_valid);

    Ok(is_valid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_check_operator() {
        let rootfs_hash = Bytes::from(vec![0x00; 32]);
        let mrtd = Bytes::from(vec![0x00; 48]);
        let rtmr0 = Bytes::from(vec![0x00; 48]);
        let rtmr3 = Bytes::from(vec![0x00; 48]);

        let _result = check_operator(rootfs_hash, mrtd, rtmr0, rtmr3)
            .await
            .unwrap();
    }
}
