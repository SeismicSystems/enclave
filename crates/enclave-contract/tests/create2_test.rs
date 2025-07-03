use enclave_contract::{deploy_factory, deploy_via_factory_create2, print_flush, ANVIL_ALICE_SK};
use std::thread::sleep;
use std::time::Duration;
use enclave_contract::UPGRADE_OPERATOR_ADDRESS;

/// Test that CREATE2 deployment produces consistent addresses
/// This test verifies that deploying the same contract with the same salt
/// always results in the same contract address
#[tokio::test(flavor = "multi_thread")]
pub async fn test_create2_consistent_addresses() -> Result<(), anyhow::Error> {
    // Set path to the factory contract's json file
    // This file is built by sforge and located in the contracts/out directory
    let factory_json_path = "contracts/out/UpgradeOperatorFactory.sol/UpgradeOperatorFactory.json";
    let reth_rpc = "http://localhost:8545";

    // Use a fixed salt for predictable testing
    let salt: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];

    print_flush("Deploying factory contract...\n");

    // Deploy the factory contract first
    let factory_address = deploy_factory(factory_json_path, ANVIL_ALICE_SK, reth_rpc)
        .await
        .map_err(|e| anyhow::anyhow!("failed to deploy factory: {:?}", e))?;

    print_flush(format!("Factory deployed at: {:?}\n", factory_address));

    // Wait a bit for the transaction to be processed
    sleep(Duration::from_secs(2));

    print_flush("Deploying first contract via CREATE2...\n");

    // Deploy first contract using CREATE2 through the factory
    let address1 = deploy_via_factory_create2(factory_address, ANVIL_ALICE_SK, reth_rpc, salt)
        .await
        .map_err(|e| anyhow::anyhow!("failed to deploy first contract via CREATE2: {:?}", e))?;

    print_flush(format!("First contract deployed at: {:?}\n", address1));

    // Wait a bit for the transaction to be processed
    sleep(Duration::from_secs(2));

    print_flush("Deploying second contract via CREATE2 with same salt and factory...\n");

    // Deploy second contract using CREATE2 with the same salt and factory
    let second_deploy_res =
        deploy_via_factory_create2(factory_address, ANVIL_ALICE_SK, reth_rpc, salt).await;
    assert!(
        second_deploy_res.is_err(),
        "Second create2 deploy should fail because you deploy to the same address"
    );

    // check that the UPGRADE_OPERATOR_ADDRESS const matches the expected address
    let expected_address = UPGRADE_OPERATOR_ADDRESS.parse::<alloy::primitives::Address>().unwrap();
    assert_eq!(address1, expected_address);

    Ok(())
}
