//! Live-TEE integration coverage run through
//! `scripts/run_integration_tests.sh`. The script prepares the runtime
//! manifest, frees the TPM, and executes this test with the required
//! privileges.

use std::time::Duration;

use crate::utils::{get_args, spawn_custodian};
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use seismic_attestation::{
    AttestationType, NetworkId, NetworkManifestV1, SeismicMeasurementPolicy,
    bindings::{binding64_from_digest32, tx_io_binding},
    verify_evidence,
};
use seismic_attestation_rpc::{AttestationRpcClient as _, TxIoAttestationResponse};
use seismic_enclave::TdxQuoteRpcClient as _;
use seismic_enclave_server::utils::{init_tracing, is_sudo};
use seismic_key_custodian::Custodian;
use seismic_key_custodian_host::state::CustodianState;

// The server reads its manifest through the same fixed `/run/seismic` handoff
// used in production, which keeps this test covering the tdx-init →
// enclave-server startup contract. This fixture is the manifest trusted by the
// relying client; the test script installs the same fixture for the server, and
// evidence verification confirms that both sides use the same network ID.
const EXPECTED_NETWORK_MANIFEST: &[u8] =
    include_bytes!("../../../network-manifest/fixtures/network-manifest-v1.json");
const NODE_STARTUP_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const EVIDENCE_RPC_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const RETRY_INTERVAL: Duration = Duration::from_secs(2);

#[serial_test::serial(attestation_evidence)]
#[tokio::test]
async fn test_get_wrapped_root_key_bootstrap() {
    init_tracing();
    // Check the starting conditions are as expected
    if !is_sudo() {
        panic!("test_get_wrapped_root_key_bootstrap: skipped (requires sudo privileges)");
    }

    // Start the genesis node's process pair: a key custodian holding a fresh
    // root key, served over its own socket, plus the attestation service.
    let node1_runtime = tempfile::tempdir().expect("create genesis runtime directory");
    let node1_socket = node1_runtime.path().join("custodian.sock");
    spawn_custodian(
        CustodianState::new_with_root_key(
            Custodian::new_as_genesis().expect("generate genesis root key"),
            node1_runtime.path().join("luks-keys"),
        )
        .expect("construct genesis custodian"),
        &node1_socket,
    );
    let args1 = get_args(0, Default::default(), node1_socket);
    let enclave_one_url = format!("http://localhost:{}", args1.port);
    let mut node1_handle = tokio::spawn(args1.start());
    let client1 = HttpClientBuilder::default()
        .build(enclave_one_url.clone())
        .expect("Unable to create enclave 1 client");
    wait_for_health(&client1, "genesis enclave", &mut node1_handle).await;

    // Start the joining node's pair with node 1 as its peer: a custodian that
    // awaits its root key through the bootstrap methods, plus the attestation
    // service. The service's RPC listener comes up after the attested
    // root-key exchange completes.
    let node2_runtime = tempfile::tempdir().expect("create joining runtime directory");
    let node2_socket = node2_runtime.path().join("custodian.sock");
    spawn_custodian(
        CustodianState::new_awaiting_root_key(node2_runtime.path().join("luks-keys")),
        &node2_socket,
    );
    let args2 = get_args(1, vec![enclave_one_url], node2_socket);
    let enclave_two_url = format!("http://localhost:{}", args2.port);
    let mut node2_handle = tokio::spawn(args2.start());
    let client2 = HttpClientBuilder::default()
        .build(enclave_two_url)
        .expect("Unable to create enclave 2 client");
    wait_for_health(&client2, "joining enclave", &mut node2_handle).await;

    // The bootstrap installed the root key in the joiner's custodian, which
    // wrote the LUKS keyfile handoff as part of that transition.
    let luks_metadata = std::fs::metadata(node2_runtime.path().join("luks-keys"))
        .expect("joining custodian wrote its LUKS keyfile");
    assert_eq!(luks_metadata.len(), 64);

    // Get keys from both and make sure they match

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
    let response = get_tx_io_attestation_evidence(&client1, epoch).await;
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

/// Wait until the server's `healthCheck` RPC returns `OK`.
///
/// The joining server binds its RPC listener after fetching and installing the
/// root key, so readiness also confirms that its bootstrap exchange completed.
async fn wait_for_health(
    client: &HttpClient,
    service: &str,
    server_handle: &mut tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let deadline = tokio::time::Instant::now() + NODE_STARTUP_TIMEOUT;

    loop {
        let last_error = match client.health_check().await {
            Ok(status) if status == "OK" => return,
            Ok(status) => format!("unexpected health response: {status}"),
            Err(error) => error.to_string(),
        };

        assert!(
            tokio::time::Instant::now() < deadline,
            "{service} did not become healthy within {NODE_STARTUP_TIMEOUT:?}: {last_error}"
        );
        tokio::select! {
            result = &mut *server_handle => {
                panic!("{service} exited before becoming healthy: {result:?}")
            }
            () = tokio::time::sleep(RETRY_INTERVAL) => {}
        }
    }
}

async fn get_tx_io_attestation_evidence(
    client: &HttpClient,
    epoch: u64,
) -> TxIoAttestationResponse {
    let deadline = tokio::time::Instant::now() + EVIDENCE_RPC_TIMEOUT;

    loop {
        match client.get_tx_io_attestation_evidence(epoch).await {
            Ok(response) => return response,
            Err(error) => {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "Unable to get tx-io attestation evidence within {EVIDENCE_RPC_TIMEOUT:?}: {error}"
                );
            }
        }
        tokio::time::sleep(RETRY_INTERVAL).await;
    }
}
