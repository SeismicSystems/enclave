use std::time::Duration;

use crate::utils::get_args;
use jsonrpsee::http_client::HttpClientBuilder;
use seismic_enclave_server::api::TdxQuoteRpcClient;
use seismic_enclave_server::utils::{init_tracing, is_sudo};

// This test expects that the booter's attestation is already allowed by the upgrade operator
// This can be set up by running the test_multisig_upgrade_operator_workflow test in the enclave-contract crate
#[serial_test::serial(attestation_agent)]
#[tokio::test]
async fn test_boot_share_root_key() {
    init_tracing();
    // Check the starting conditions are as expected
    if !is_sudo() {
        panic!("test_boot_share_root_key: skipped (requires sudo privileges)");
    }

    // Start first enclave as genesis node
    let args1 = get_args(0, true, Default::default());
    let enclave_one_url = format!("http://localhost:{}", args1.port);
    let node1_handle = tokio::spawn(args1.start());

    // sleep some time to allow him to start up
    tokio::time::sleep(Duration::from_secs(1)).await;

    // start second enclave with node1 as his peer
    let args2 = get_args(1, false, vec![enclave_one_url.clone()]);
    let enclave_two_url = format!("http://localhost:{}", args2.port);
    let node2_handle = tokio::spawn(args2.start());
    // sleep some time to allow them to share keys
    tokio::time::sleep(Duration::from_secs(10)).await;

    // Get keys from both and make sure they match
    let client1 = HttpClientBuilder::default()
        .build(enclave_one_url)
        .expect("Unable to connect to enclave 1");
    let client2 = HttpClientBuilder::default()
        .build(enclave_two_url)
        .expect("Unable to connect to enclave 2");

    let keys1 = client1
        .get_purpose_keys(0)
        .await
        .expect("Unable to get purpose keys");
    let keys2 = client2
        .get_purpose_keys(0)
        .await
        .expect("Unable to get purpose keys");

    // Ensure they are the same from both nodes
    assert_eq!(keys1.rng_keypair.secret, keys2.rng_keypair.secret);
    assert_eq!(keys1.snapshot_key_bytes, keys2.snapshot_key_bytes);
    assert_eq!(keys1.tx_io_sk, keys2.tx_io_sk);

    // test the other endpoints
    assert_eq!(client1.health_check().await.unwrap(), "OK".to_string());
    let evidence = client1.get_attestation_evidence().await.unwrap();
    client1
        .eval_attestation_evidence(evidence.hcl_report, evidence.quote)
        .await
        .unwrap();

    node1_handle.abort();
    node2_handle.abort();
}
