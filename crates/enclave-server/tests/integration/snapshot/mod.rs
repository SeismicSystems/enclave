use crate::utils::{deploy_contract, ANVIL_ALICE_PK};

use seismic_enclave::request_types::{
    PrepareEncryptedSnapshotRequest, RestoreFromEncryptedSnapshotRequest,
};
use seismic_enclave::{
    EnclaveClientBuilder, ENCLAVE_DEFAULT_ENDPOINT_IP, ENCLAVE_DEFAULT_ENDPOINT_PORT,
};
use seismic_enclave_server::utils::test_utils::is_sudo;
use seismic_enclave::rpc::SyncEnclaveApiClient;

#[cfg(not(feature = "supervisorctl"))]
use seismic_enclave_server::utils::service::reth_is_running;
#[cfg(feature = "supervisorctl")]
use seismic_enclave_server::utils::supervisorctl::reth_is_running;

use crate::utils::print_flush;
use alloy::primitives::Bytes;
use seismic_enclave_server::snapshot::{
    check_operator, DATA_DISK_DIR, RETH_DATA_DIR, SNAPSHOT_DIR, SNAPSHOT_FILE,
};
use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::path::Path;
use std::thread::sleep;
use std::time::Duration;

#[tokio::test]
pub async fn test_snapshot_integration_handlers() -> Result<(), anyhow::Error> {
    print_flush("Running test_snapshot_integration_handlers. Expected runtime is ~90 sec\n");
    // Check the starting conditions are as expected
    assert!(is_sudo(), "Must be run as sudo");
    assert!(
        Path::new(format!("{}/db/mdbx.dat", RETH_DATA_DIR).as_str()).exists(),
        "Test startup error: MDBX misconfigured"
    );
    assert!(
        !Path::new(format!("{}/{}.enc", SNAPSHOT_DIR, SNAPSHOT_FILE).as_str()).exists(),
        "Test startup error: Encrypted snapshot already exists"
    );
    assert!(reth_is_running(), "Test startup error: Reth is not running");
    // set path to the contract's json file
    // this file can be recreated `forge build`
    // assumes test is run from the root of the enclave-server crate
    let foundry_json_path = "tests/integration/snapshot/UpgradeOperator.json";
    let enclave_addr =
        SocketAddr::from((ENCLAVE_DEFAULT_ENDPOINT_IP, ENCLAVE_DEFAULT_ENDPOINT_PORT));
    let enclave_client = EnclaveClientBuilder::new()
        .ip(enclave_addr.ip().to_string())
        .port(enclave_addr.port())
        .build()
        .unwrap();
    let reth_rpc = "http://localhost:8545";

    // Deploy UpgradeOperator contract
    deploy_contract(foundry_json_path, ANVIL_ALICE_PK, reth_rpc)
        .await
        .map_err(|e| anyhow::anyhow!("failed to deploy UpgradeOperator contract: {:?}", e))?;
    // deploy 2 more times to trigger the reth persistence threshhold
    // and have the first block save to disk
    // based on the assumption that reth is run with the  --dev.block-max-transactions 1 flag
    deploy_contract(foundry_json_path, ANVIL_ALICE_PK, reth_rpc)
        .await
        .map_err(|e| anyhow::anyhow!("failed to deploy UpgradeOperator contract 2: {:?}", e))?;
    deploy_contract(foundry_json_path, ANVIL_ALICE_PK, reth_rpc)
        .await
        .map_err(|e| anyhow::anyhow!("failed to deploy UpgradeOperator contract 3: {:?}", e))?;
    sleep(Duration::from_secs(2));

    // Create encrypted snapshot
    let prepare_req = PrepareEncryptedSnapshotRequest {};
    let prepare_resp = enclave_client
        .prepare_encrypted_snapshot(prepare_req)
        .unwrap();
    assert!(prepare_resp.success);
    assert!(Path::new(format!("{}/{}.enc", DATA_DISK_DIR, SNAPSHOT_FILE).as_str()).exists());
    assert!(reth_is_running());

    // Delete files that will be recovered
    fs::remove_dir_all(RETH_DATA_DIR).unwrap();

    // Restore from encrypted snapshot
    assert!(!Path::new(format!("{}/db/mdbx.dat", RETH_DATA_DIR).as_str()).exists());
    assert!(Path::new(format!("{}/{}.enc", DATA_DISK_DIR, SNAPSHOT_FILE).as_str()).exists());
    let restore_req = RestoreFromEncryptedSnapshotRequest {};
    let restore_resp = enclave_client
        .restore_from_encrypted_snapshot(restore_req)
        .unwrap();
    assert!(restore_resp.success);
    assert!(Path::new(format!("{}/db/mdbx.dat", RETH_DATA_DIR).as_str()).exists());
    assert!(reth_is_running());

    // Check that the chain data is recovered
    // E.g. by checking that the UpgradeOperator contract is deployed
    let sleep_sec = 45; // 30 sec is not enough sometimes
    print_flush("Finished restoring. Checking operator contract...");
    print_flush(format!("Sleeping for {} seconds... \n", sleep_sec));
    std::io::stdout().flush().unwrap();
    sleep(Duration::from_secs(sleep_sec)); // wait to avoid a connection refused error
    let rootfs_hash = Bytes::from(vec![0x00; 32]);
    let mrtd = Bytes::from(vec![0x00; 48]);
    let rtmr0 = Bytes::from(vec![0x00; 48]);
    let rtmr3 = Bytes::from(vec![0x00; 48]);

    let _result = check_operator(rootfs_hash, mrtd, rtmr0, rtmr3)
        .await
        .unwrap();

    Ok(())
}

/////////////////////////////////////////////////////////////////////////////////
/// Manual testing helpers
/// Useful for checking things work across machines
/////////////////////////////////////////////////////////////////////////////////

#[tokio::test]
pub async fn run_restore() -> Result<(), anyhow::Error> {
    assert!(is_sudo(), "Must be run as sudo");

    let enclave_addr =
        SocketAddr::from((ENCLAVE_DEFAULT_ENDPOINT_IP, ENCLAVE_DEFAULT_ENDPOINT_PORT));
    let enclave_client = EnclaveClientBuilder::new()
        .ip(enclave_addr.ip().to_string())
        .port(enclave_addr.port())
        .build()
        .unwrap();

    assert!(reth_is_running());
    assert!(Path::new(format!("{}/{}.enc", DATA_DISK_DIR, SNAPSHOT_FILE).as_str()).exists());
    let restore_req = RestoreFromEncryptedSnapshotRequest {};
    let restore_resp = enclave_client
        .restore_from_encrypted_snapshot(restore_req)
        .unwrap();
    assert!(
        restore_resp.success,
        "Restore failed: {}",
        restore_resp.error
    );
    //  restore_from_encrypted_snapshot(RETH_DATA_DIR, DATA_DISK_DIR, SNAPSHOT_DIR, SNAPSHOT_FILE)?;
    assert!(reth_is_running());
    Ok(())
}
