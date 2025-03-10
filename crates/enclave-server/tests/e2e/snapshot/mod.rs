use crate::utils::{deploy_contract, ANVIL_ALICE_PK};
// use crate::utils::test_utils::get_random_port;
// use seismic_enclave::rpc::{BuildableServer, EnclaveApiClient};
// use seismic_enclave::snapshot::{
//     PrepareEncryptedSnapshotRequest, PrepareEncryptedSnapshotResponse,
//     RestoreFromEncryptedSnapshotRequest, RestoreFromEncryptedSnapshotResponse,
// };
// use seismic_enclave::{EnclaveClient, ENCLAVE_DEFAULT_ENDPOINT_ADDR};
// use seismic_enclave_server::server::{EnclaveServer, init_tracing};
use seismic_enclave_server::snapshot::*;
use seismic_enclave_server::utils::supervisor::reth_is_running;
use seismic_enclave_server::utils::test_utils::is_sudo;

use alloy_primitives::Bytes;
// use std::net::SocketAddr;
use std::path::Path;
use std::process::Command;
use std::thread::sleep;
use std::time::Duration;

#[tokio::test]
pub async fn test_snapshot_integration_direct() -> Result<(), anyhow::Error> {
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
    assert!(reth_is_running(), "Test startup error: Reth is not running");
    // set path to the contract's json file
    // this file can be recreated `forge build`
    // assumes test is run from the root of the enclave-server crate
    let foundry_json_path = "tests/e2e/snapshot/UpgradeOperator.json";

    // Deploy UpgradeOperator contract
    let reth_rpc = "http://localhost:8545";
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
    prepare_encrypted_snapshot(RETH_DB_DIR, DATA_DISK_DIR, SNAPSHOT_FILE, MDBX_FILE)?;
    assert!(Path::new(format!("{}/{}.enc", DATA_DISK_DIR, SNAPSHOT_FILE).as_str()).exists());
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
    assert!(Path::new(format!("{}/{}.enc", DATA_DISK_DIR, SNAPSHOT_FILE).as_str()).exists());
    restore_from_encrypted_snapshot(RETH_DB_DIR, DATA_DISK_DIR, SNAPSHOT_FILE).unwrap();
    assert!(Path::new(format!("{}/{}", RETH_DB_DIR, MDBX_FILE).as_str()).exists());
    assert!(reth_is_running());

    // Check that the chain data is recovered
    // E.g. by checking that the UpgradeOperator contract is deployed
    let sleep_sec = 30; // 15 sec is not enough
    println!("Finished restoring. Checking operator contract...");
    println!("Sleeping for {} seconds...", sleep_sec);
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

// #[tokio::test]
// pub async fn test_snapshot_integration_handlers() -> Result<(), anyhow::Error> {
//     // init_tracing();
//     assert!(is_sudo(), "Must be run as sudo");
//     assert!(
//         Path::new(format!("{}/{}", RETH_DB_DIR, MDBX_FILE).as_str()).exists(),
//         "Test startup error: MDBX misconfigured"
//     );
//     assert!(
//         !Path::new(format!("{}/{}.enc", RETH_DB_DIR, SNAPSHOT_FILE).as_str()).exists(),
//         "Test startup error: Encrypted snapshot already exists"
//     );
//     assert!(reth_is_running(), "Test startup error: Reth is not running");
//     // set path to the contract's json file
//     // this file can be recreated `forge build`
//     // assumes test is run from the root of the enclave-server crate
//     let foundry_json_path = "tests/e2e/snapshot/UpgradeOperator.json";

//     // set up rpc server
//     // spawn a seperate thread for the server, otherwise the test will hang
//     let port = get_random_port();
//     let addr = SocketAddr::from((ENCLAVE_DEFAULT_ENDPOINT_ADDR, port));
//     let _server_handle = EnclaveServer::new(addr).start().await.unwrap();
//     sleep(Duration::from_secs(4));
//     let enclave_client = EnclaveClient::new(format!("http://{}:{}", addr.ip(), addr.port()));

//     let reth_rpc = "http://localhost:8545";
//     deploy_contract(foundry_json_path, ANVIL_ALICE_PK, reth_rpc)
//         .await
//         .map_err(|e| anyhow::anyhow!("failed to deploy UpgradeOperator contract: {:?}", e))?;
//     // deploy 2 more times to trigger the reth persistence threshhold
//     // and have the first block save to disk
//     // based on the assumption that reth is run with the  --dev.block-max-transactions 1 flag
//     deploy_contract(foundry_json_path, ANVIL_ALICE_PK, reth_rpc)
//         .await
//         .map_err(|e| anyhow::anyhow!("failed to deploy UpgradeOperator contract 2: {:?}", e))?;
//     deploy_contract(foundry_json_path, ANVIL_ALICE_PK, reth_rpc)
//         .await
//         .map_err(|e| anyhow::anyhow!("failed to deploy UpgradeOperator contract 3: {:?}", e))?;

//     // Create encrypted snapshot
//     let prepare_req = PrepareEncryptedSnapshotRequest {};
//     let prepare_resp = enclave_client
//         .prepare_encrypted_snapshot(prepare_req)
//         .await
//         .unwrap();
//     assert!(prepare_resp.success);
//     assert!(Path::new(format!("{}/{}.enc", RETH_DB_DIR, SNAPSHOT_FILE).as_str()).exists());
//     assert!(reth_is_running());

//     // download encrypted snapshot
//     let download_req = DownloadEncryptedSnapshotRequest {};
//     let download_resp = enclave_client
//         .download_encrypted_snapshot(download_req)
//         .await
//         .unwrap();
//     assert!(download_resp.encrypted_snapshot.len() > 0);
//     assert!(reth_is_running());

//     // delete files that will be recovered
//     let files = [SNAPSHOT_FILE, MDBX_FILE];
//     for file in &files {
//         let path = format!("{}/{}", RETH_DB_DIR, file);
//         Command::new("sudo")
//             .arg("rm")
//             .arg(&path)
//             .output()
//             .expect("Failed to execute command");
//     }

//     // Upload encrypted snapshot
//     let upload_req = UploadEncryptedSnapshotRequest {
//         encrypted_snapshot: download_resp.encrypted_snapshot,
//     };
//     let upload_resp = enclave_client
//         .upload_encrypted_snapshot(upload_req)
//         .await
//         .unwrap();
//     assert!(upload_resp.success);
//     assert!(reth_is_running());

//     // Restore from encrypted snapshot
//     let restore_req = RestoreFromEncryptedSnapshotRequest {};
//     let restore_resp = enclave_client
//         .restore_from_encrypted_snapshot(restore_req)
//         .await
//         .unwrap();
//     assert!(restore_resp.success);
//     assert!(reth_is_running());

//     // Check that the chain data is recovered
//     // E.g. by checking that the UpgradeOperator contract is deployed
//     let sleep_sec = 20; // 15 sec is not enough
//     println!("Finished restoring. Checking operator contract...");
//     println!("Sleeping for {} seconds...", sleep_sec);
//     sleep(Duration::from_secs(sleep_sec)); // wait to avoid a connection refused error
//     let rootfs_hash = Bytes::from(vec![0x00; 32]);
//     let mrtd = Bytes::from(vec![0x00; 48]);
//     let rtmr0 = Bytes::from(vec![0x00; 48]);
//     let rtmr3 = Bytes::from(vec![0x00; 48]);

//     let _result = check_operator(rootfs_hash, mrtd, rtmr0, rtmr3)
//         .await
//         .unwrap();

//     Ok(())
// }
