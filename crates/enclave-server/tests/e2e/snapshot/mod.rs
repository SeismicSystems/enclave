use crate::utils::{deploy_contract, ANVIL_ALICE_PK};
use seismic_enclave_server::snapsync::check_operator::check_operator;
use seismic_enclave_server::snapsync::*;
use seismic_enclave_server::utils::supervisor::reth_is_running;

use alloy_primitives::Bytes;
use seismic_enclave_server::utils::test_utils::is_sudo;
use std::path::Path;
use std::process::Command;

#[tokio::test]
pub async fn full_snapshot_test() -> Result<(), anyhow::Error> {
    assert!(is_sudo(), "Must be run as sudo");
    // Check the starting conditions are as expected
    assert!(
        Path::new(format!("{}/{}", RETH_DB_DIR, MDBX_FILE).as_str()).exists(),
        "Startup error: MDBX misconfigured"
    );
    assert!(
        !Path::new(format!("{}/{}.enc", RETH_DB_DIR, SNAPSHOT_FILE).as_str()).exists(),
        "Startup error: Encrypted snapshot already exists"
    );
    assert!(
        reth_is_running(),
        "Startup error: Reth is not running"
    );

    // Deploy UpgradeOperator contract
    let rpc = "http://localhost:8545";
    let foundry_json_path = "tests/e2e/snapshot/UpgradeOperator.json";
    deploy_contract(foundry_json_path, ANVIL_ALICE_PK, rpc).await.map_err(
        |e| anyhow::anyhow!("failed to deploy UpgradeOperator contract: {:?}", e),
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
    let rootfs_hash = Bytes::from(vec![0x00; 32]);
    let mrtd = Bytes::from(vec![0x00; 48]);
    let rtmr0 = Bytes::from(vec![0x00; 48]);
    let rtmr3 = Bytes::from(vec![0x00; 48]);

    let _result = check_operator(rootfs_hash, mrtd, rtmr0, rtmr3)
        .await
        .unwrap();

    Ok(())
}


#[tokio::test]
pub async fn runner() -> Result<(), anyhow::Error> {
    let rootfs_hash = Bytes::from(vec![0x00; 32]);
    let mrtd = Bytes::from(vec![0x00; 48]);
    let rtmr0 = Bytes::from(vec![0x00; 48]);
    let rtmr3 = Bytes::from(vec![0x00; 48]);

    let _result = check_operator(rootfs_hash, mrtd, rtmr0, rtmr3)
        .await
        .unwrap();

    Ok(())
}