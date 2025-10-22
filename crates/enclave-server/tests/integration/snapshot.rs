use crate::utils::{get_balance, send_eth};
use enclave_contract::{ANVIL_ALICE_SK, ANVIL_BOB_SK};

use seismic_enclave::boot_genesis_streamlined_async;
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
    boot_genesis_streamlined_async(&enclave_client)
        .await
        .unwrap();

    // Get Alice's address from her private key
    let alice_signer: alloy::signers::local::PrivateKeySigner = ANVIL_ALICE_SK.parse().unwrap();
    let alice_address = alice_signer.address();

    // Check initial balance
    print_flush("Checking initial account balance...\n");
    let initial_balance = get_balance(alice_address, reth_rpc)
        .await
        .map_err(|e| anyhow::anyhow!("failed to get initial balance: {:?}", e))?;
    print_flush(format!("Initial balance: {} wei\n", initial_balance));

    // Send ETH transactions to trigger the reth persistence threshold
    // and have the first block save to disk
    // based on the assumption that reth is run with the --dev.block-max-transactions 1 flag
    print_flush("Sending ETH transactions for persistence threshold...\n");
    // Send ETH from Alice to zero address (burning ETH) - burn a small amount
    let burn_amount = 1_000_000_000u128; // 1 gwei
    send_eth(
        ANVIL_ALICE_SK,
        alloy::primitives::Address::ZERO,
        burn_amount,
        reth_rpc,
    )
    .await
    .map_err(|e| anyhow::anyhow!("failed to send ETH to zero address: {:?}", e))?;
    // make two more transactions to trigger the persistence threshold for Alice
    send_eth(
        ANVIL_BOB_SK,
        alloy::primitives::Address::ZERO,
        burn_amount,
        reth_rpc,
    )
    .await
    .map_err(|e| anyhow::anyhow!("failed to send ETH to zero address: {:?}", e))?;
    send_eth(
        ANVIL_BOB_SK,
        alloy::primitives::Address::ZERO,
        burn_amount,
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
    assert!(
        restore_resp.success,
        "restore_from_encrypted_snapshot failed: {}",
        restore_resp.error
    );
    // give reth some time to start back up
    sleep(Duration::from_secs(15));
    assert!(Path::new(format!("{}/db/mdbx.dat", RETH_DATA_DIR).as_str()).exists());
    assert!(reth_is_running());

    // Check that the chain data is recovered
    // E.g. by checking that Alice's balance is lower than the initial balance
    let sleep_sec = 45; // 30 sec is not enough sometimes
    print_flush("Finished restoring. Checking account balance...");
    print_flush(format!("Sleeping for {} seconds... \n", sleep_sec));
    sleep(Duration::from_secs(sleep_sec)); // wait to avoid a connection refused error

    // Check final balance
    let final_balance = get_balance(alice_address, reth_rpc)
        .await
        .map_err(|e| anyhow::anyhow!("failed to get final balance: {:?}", e))?;
    print_flush(format!("Final balance: {} wei\n", final_balance));

    // Verify that the balance decreased (due to burning ETH)
    assert!(
        final_balance < initial_balance,
        "Balance should have decreased after burning ETH. Initial: {}, Final: {}",
        initial_balance,
        final_balance
    );

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
