//! Live-TEE integration coverage run through
//! `scripts/run_integration_tests.sh`. The script prepares the runtime
//! manifest, frees the TPM, and executes this test with the required
//! privileges.

use std::time::Duration;

use crate::utils::get_args;
use jsonrpsee::http_client::HttpClientBuilder;
use seismic_attestation::{
    AttestationType, NetworkId, NetworkManifestV1, SeismicMeasurementPolicy,
    bindings::{binding64_from_digest32, tx_io_binding},
    verify_evidence,
};
use seismic_attestation_rpc::AttestationRpcClient as _;
use seismic_enclave::TdxQuoteRpcClient as _;
use seismic_enclave_server::utils::{init_tracing, is_sudo};

// The server reads its manifest through the same fixed `/run/seismic` handoff
// used in production, which keeps this test covering the tdx-init →
// enclave-server startup contract. This fixture is the manifest trusted by the
// relying client; the test script installs the same fixture for the server, and
// evidence verification confirms that both sides use the same network ID.
const EXPECTED_NETWORK_MANIFEST: &[u8] =
    include_bytes!("../../../network-manifest/fixtures/network-manifest-v1.json");

#[serial_test::serial(attestation_evidence)]
#[tokio::test]
async fn test_get_wrapped_root_key_bootstrap() {
    init_tracing();
    // Check the starting conditions are as expected
    if !is_sudo() {
        panic!("test_get_wrapped_root_key_bootstrap: skipped (requires sudo privileges)");
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

    assert_eq!(client1.health_check().await.unwrap(), "OK".to_string());

    // Act as the relying party for tx-io evidence: derive the expected binding
    // independently from the manifest bytes, response key, and requested
    // epoch, then verify through seismic-attestation.
    let epoch = 0;
    let response = client1
        .get_tx_io_attestation_evidence(epoch)
        .await
        .expect("Unable to get tx-io attestation evidence");
    assert_eq!(response.epoch, epoch);
    assert_eq!(response.tx_io_pk, keys1.tx_io_pk);

    NetworkManifestV1::from_json_bytes(EXPECTED_NETWORK_MANIFEST)
        .expect("Relying client's network manifest is invalid");
    let network_id = NetworkId::from_manifest_bytes(EXPECTED_NETWORK_MANIFEST);
    let expected_digest =
        tx_io_binding(&network_id, &response.tx_io_pk.serialize(), response.epoch);
    let expected_binding = binding64_from_digest32(expected_digest);

    verify_evidence(
        response.evidence.clone(),
        expected_binding,
        test_measurement_policy(),
    )
    .await
    .expect("Relying client rejected valid tx-io evidence");

    let wrong_epoch_digest = tx_io_binding(
        &network_id,
        &response.tx_io_pk.serialize(),
        response.epoch + 1,
    );
    assert!(
        verify_evidence(
            response.evidence.clone(),
            binding64_from_digest32(wrong_epoch_digest),
            test_measurement_policy(),
        )
        .await
        .is_err(),
        "evidence verified against the wrong epoch binding"
    );

    let mut tampered_evidence = response.evidence;
    assert!(!tampered_evidence.attestation.is_empty());
    // Azure evidence is a JSON document. Invalid UTF-8 gives us a
    // deterministic malformed-evidence case.
    tampered_evidence.attestation[0] = 0xff;
    assert!(
        verify_evidence(
            tampered_evidence,
            expected_binding,
            test_measurement_policy(),
        )
        .await
        .is_err(),
        "tampered evidence verified successfully"
    );

    node1_handle.abort();
    node2_handle.abort();
}

/// The bootstrap path uses the same intentionally temporary permissive policy.
/// This test is about verifier ownership and transcript integrity; production
/// measurement admission is covered by the separately tracked on-chain policy.
fn test_measurement_policy() -> SeismicMeasurementPolicy {
    SeismicMeasurementPolicy::dangerously_accept_any_for_testing(AttestationType::AzureTdx)
}
