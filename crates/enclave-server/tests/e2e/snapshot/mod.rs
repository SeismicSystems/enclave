use crate::utils::{deploy_contract, ANVIL_ALICE_PK};
use seismic_enclave_server::snapshot::check_operator::check_operator;
use seismic_enclave_server::snapshot::*;
use seismic_enclave_server::utils::supervisor::reth_is_running;

use alloy_primitives::Bytes;
use seismic_enclave_server::utils::test_utils::is_sudo;
use tokio::time::sleep;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

#[tokio::test]
pub async fn full_snapshot_test() -> Result<(), anyhow::Error> {
    // Check the starting conditions are as expected
    assert!(is_sudo(), "Must be run as sudo");
    assert!(
        Path::new(format!("{}/{}", RETH_DB_DIR, MDBX_FILE).as_str()).exists(),
        "Test startup error: MDBX misconfigured"
    );
    assert!(
        !Path::new(format!("{}/{}.enc", RETH_DB_DIR, SNAPSHOT_FILE).as_str()).exists(),
        "Test startup error: Encrypted snapshot already exists"
    );
    assert!(
        reth_is_running(),
        "Test startup error: Reth is not running"
    );
    // set path to the contract's json file
    // this file can be recreated `forge build`
    // assumes test is run from the root of the enclave-server crate
    let foundry_json_path = "tests/e2e/snapshot/UpgradeOperator.json";  

    // Deploy UpgradeOperator contract
    let rpc = "http://localhost:8545";
    deploy_contract(foundry_json_path, ANVIL_ALICE_PK, rpc).await.map_err(
        |e| anyhow::anyhow!("failed to deploy UpgradeOperator contract: {:?}", e),
    )?;
    // deploy 2 more times to trigger the reth persistence threshhold
    // and have the first block save to disk
    // based on the assumption that reth is run with the  --dev.block-max-transactions 1 flag
    deploy_contract(foundry_json_path, ANVIL_ALICE_PK, rpc).await.map_err(
        |e| anyhow::anyhow!("failed to deploy UpgradeOperator contract 2: {:?}", e),
    )?;
    deploy_contract(foundry_json_path, ANVIL_ALICE_PK, rpc).await.map_err(
        |e| anyhow::anyhow!("failed to deploy UpgradeOperator contract 3: {:?}", e),
    )?;

    // Create encrypted snapshot
    create_encrypted_snapshot(RETH_DB_DIR, SNAPSHOT_FILE, MDBX_FILE)?;
    assert!(Path::new(format!("{}/{}.enc", RETH_DB_DIR, SNAPSHOT_FILE).as_str()).exists());
    assert!(reth_is_running());

    // delete files that will be recovered
    let files = [SNAPSHOT_FILE, MDBX_FILE];
    for file in &files {
        let path = format!("{}/{}", RETH_DB_DIR, file);
        Command::new("sudo")
            .arg("rm")
            .arg(&path)
            .output()
            .expect("Failed to execute command");
    }

    // Restore from encrypted snapshot
    assert!(!Path::new(format!("{}/{}", RETH_DB_DIR, MDBX_FILE).as_str()).exists());
    assert!(Path::new(format!("{}/{}.enc", RETH_DB_DIR, SNAPSHOT_FILE).as_str()).exists());
    restore_from_encrypted_snapshot(RETH_DB_DIR, SNAPSHOT_FILE)
        .unwrap();
    assert!(Path::new(format!("{}/{}", RETH_DB_DIR, MDBX_FILE).as_str()).exists());
    assert!(reth_is_running());

    // Check that the chain data is recovered
    // E.g. by checking that the UpgradeOperator contract is deployed
    let sleep_sec = 20; // 15 sec is not enough
    println!("Finished restoring. Checking operator contract...");
    println!("Sleeping for {} seconds...", sleep_sec);
    sleep(Duration::from_secs(sleep_sec)).await; // wait to avoid a connection refused error
    let rootfs_hash = Bytes::from(vec![0x00; 32]);
    let mrtd = Bytes::from(vec![0x00; 48]);
    let rtmr0 = Bytes::from(vec![0x00; 48]);
    let rtmr3 = Bytes::from(vec![0x00; 48]);
    
    let _result = check_operator(rootfs_hash, mrtd, rtmr0, rtmr3)
        .await
        .unwrap();

    Ok(())
}
