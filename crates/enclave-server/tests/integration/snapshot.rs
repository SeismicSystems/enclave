use enclave_contract::{
    check_proposal_status_v1, deploy_factory, deploy_upgrade_operator_with_multisig, send_eth,
    ProposalParamsV1, ANVIL_ALICE_SK, ANVIL_BOB_SK,
};

use seismic_enclave::boot_genesis_streamlined;
use seismic_enclave::request_types::{
    PrepareEncryptedSnapshotRequest, RestoreFromEncryptedSnapshotRequest,
};
use seismic_enclave::rpc::SyncEnclaveApiClient;
use seismic_enclave::{
    EnclaveClientBuilder, ENCLAVE_DEFAULT_ENDPOINT_IP, ENCLAVE_DEFAULT_ENDPOINT_PORT,
};
use seismic_enclave_server::utils::test_utils::is_sudo;

#[cfg(not(feature = "supervisorctl"))]
use seismic_enclave_server::utils::service::reth_is_running;
#[cfg(feature = "supervisorctl")]
use seismic_enclave_server::utils::supervisorctl::reth_is_running;

use seismic_enclave_server::snapshot::{DATA_DISK_DIR, RETH_DATA_DIR, SNAPSHOT_DIR, SNAPSHOT_FILE};
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::thread::sleep;
use std::time::Duration;

/// Prints a string to standard output and immediately flushes the output buffer.
/// Useful to see prints immediately during long-running Cargo tests.
pub fn print_flush<S: AsRef<str>>(s: S) {
    use std::io::Write;
    let stdout = std::io::stdout();
    let mut handle = stdout.lock(); // lock ensures safe writing
    write!(handle, "{}", s.as_ref()).unwrap();
    handle.flush().unwrap();
}

// This test assumes the enclave-server and reth are both running
// with the relevant service manager
#[tokio::test(flavor = "multi_thread")]
pub async fn test_snapshot_integration_handlers() -> Result<(), anyhow::Error> {
    print_flush("Running test_snapshot_integration_handlers. Expected runtime is ~90 sec\n");
    // Check the starting conditions are as expected
    assert!(is_sudo(), "Must be run as sudo");
    assert!(
        Path::new(format!("{}/db/mdbx.dat", RETH_DATA_DIR).as_str()).exists(),
        "Test startup error: Reth mbdx.dat missing or misconfigured. Expected to find it at {}/db/mdbx.dat", RETH_DATA_DIR
    );
    assert!(
        !Path::new(format!("{}/{}.enc", SNAPSHOT_DIR, SNAPSHOT_FILE).as_str()).exists(),
        "Test startup error: Encrypted snapshot already exists"
    );
    assert!(
        Path::new(DATA_DISK_DIR).is_dir(),
        "Test startup error: DATA_DISK_DIR missing or misconfigured. Expected to find a directory at {}", DATA_DISK_DIR
    );
    assert!(reth_is_running(), "Test startup error: Reth is not running");

    // Set up clients
    let enclave_addr =
        SocketAddr::from((ENCLAVE_DEFAULT_ENDPOINT_IP, ENCLAVE_DEFAULT_ENDPOINT_PORT));
    let enclave_client = EnclaveClientBuilder::new()
        .ip(enclave_addr.ip().to_string())
        .port(enclave_addr.port())
        .timeout(Duration::from_secs(120)) // snapshot takes a while
        .build()
        .unwrap();
    let reth_rpc = "http://localhost:8545";

    // Boot genesis so we can interact with the enclaver-server
    boot_genesis_streamlined(&enclave_client).await.unwrap();

    // Deploy factory contract
    print_flush("Deploying factory contract...\n");
    // Set paths to the contract JSON files
    let factory_json_path =
        "../enclave-contract/contracts/out/UpgradeOperatorFactory.sol/UpgradeOperatorFactory.json";
    let factory_address = deploy_factory(factory_json_path, ANVIL_ALICE_SK, reth_rpc)
        .await
        .map_err(|e| anyhow::anyhow!("failed to deploy factory: {:?}", e))?;
    print_flush(format!("Factory deployed at: {:?}\n", factory_address));

    // Deploy UpgradeOperator and MultisigUpgradeOperator contracts via CREATE2
    print_flush("Deploying UpgradeOperator and MultisigUpgradeOperator via CREATE2...\n");
    let upgrade_operator_salt: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];
    let multisig_salt: [u8; 32] = [
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e,
        0x3f, 0x40,
    ];
    let (operator_address, _multisig_address) = deploy_upgrade_operator_with_multisig(
        factory_address,
        ANVIL_ALICE_SK,
        reth_rpc,
        upgrade_operator_salt,
        multisig_salt,
    )
    .await
    .map_err(|e| anyhow::anyhow!("failed to deploy contracts via CREATE2: {:?}", e))?;
    print_flush(format!(
        "UpgradeOperator deployed at: {:?}\n",
        operator_address
    ));

    // Double check that we can currently ready the contract
    // Create test proposal parameters using the new structure
    let test_params = ProposalParamsV1::test_params();

    let _result = check_proposal_status_v1(operator_address, reth_rpc, &test_params).await?;

    // Send ETH transactions to trigger the reth persistence threshold
    // and have the first block save to disk
    // based on the assumption that reth is run with the --dev.block-max-transactions 1 flag
    print_flush("Sending ETH transactions for persistence threshold...\n");
    // Send ETH from Alice to zero address (burning ETH)
    send_eth(
        ANVIL_ALICE_SK,
        alloy::primitives::Address::ZERO,
        1u128,
        reth_rpc,
    )
    .await
    .map_err(|e| anyhow::anyhow!("failed to send ETH to zero address: {:?}", e))?;
    send_eth(
        ANVIL_BOB_SK,
        alloy::primitives::Address::ZERO,
        1u128,
        reth_rpc,
    )
    .await
    .map_err(|e| anyhow::anyhow!("failed to send ETH to zero address: {:?}", e))?;
    print_flush("Sent ETH. Starting to prepare snapshot and restore\n");

    sleep(Duration::from_secs(2));

    // Create encrypted snapshot
    let prepare_req = PrepareEncryptedSnapshotRequest {};
    let prepare_resp = enclave_client
        .prepare_encrypted_snapshot(prepare_req)
        .unwrap();
    assert!(
        prepare_resp.success,
        "prepare_encrypted_snapshot failed: {}",
        prepare_resp.error
    );
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
    sleep(Duration::from_secs(sleep_sec)); // wait to avoid a connection refused error

    // Create test proposal parameters using the new structure
    let test_params = ProposalParamsV1::test_params();

    let _result = check_proposal_status_v1(operator_address, reth_rpc, &test_params).await?;

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
