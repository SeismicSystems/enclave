use seismic_enclave_server::snapsync::*;
use seismic_enclave_server::snapsync::check_operator::check_operator;
use seismic_enclave_server::utils::supervisor::reth_is_running;


use std::path::Path;
use alloy_primitives::{Address, Bytes};

#[test]
fn test_create_encrypted_snapshot() {
    assert!(Path::new(format!("{}/{}", RETH_DB_DIR, MDBX_FILE).as_str()).exists());
    assert!(!Path::new(format!("{}/{}.enc", RETH_DB_DIR, SNAPSHOT_FILE).as_str()).exists());
    assert!(reth_is_running()); // assumes reth is running when the test starts

    create_encrypted_snapshot(RETH_DB_DIR, SNAPSHOT_FILE, MDBX_FILE).unwrap();
    assert!(Path::new(format!("{}/{}.enc", RETH_DB_DIR, SNAPSHOT_FILE).as_str()).exists());
    assert!(reth_is_running());
}

#[test]
fn test_restore_from_encrypted_snapshot() {
    assert!(!Path::new(format!("{}/{}", RETH_DB_DIR, MDBX_FILE).as_str()).exists());
    assert!(Path::new(format!("{}/{}.enc", RETH_DB_DIR, SNAPSHOT_FILE).as_str()).exists());
    assert!(reth_is_running()); // assumes reth is running when the test starts

    restore_from_encrypted_snapshot(RETH_DB_DIR, format!("{}.enc", SNAPSHOT_FILE).as_str()).unwrap();
    assert!(Path::new(format!("{}/{}", RETH_DB_DIR, MDBX_FILE).as_str()).exists());
    assert!(reth_is_running());
}

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


#[test]
fn full_snapshot_test() {
    // assumes reth is running from block zero

}

