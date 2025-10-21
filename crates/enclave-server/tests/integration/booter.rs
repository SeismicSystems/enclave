use seismic_enclave::rpc::EnclaveApiServer;
use seismic_enclave::AttestationEvalEvidenceRequest;
use seismic_enclave::ShareRootKeyRequest;
use seismic_enclave_server::key_manager::KeyManager;
use seismic_enclave_server::server::boot::Booter;
use seismic_enclave_server::server::engine::engine_mock_booted;
use seismic_enclave_server::server::engine::AttestationEngine;
use seismic_enclave_server::utils::test_utils::is_sudo;
use seismic_enclave_server::utils::test_utils::pub_key_eval_request;
use serial_test::serial;

#[cfg(not(feature = "supervisorctl"))]
use seismic_enclave_server::utils::service::reth_is_running;
#[cfg(feature = "supervisorctl")]
use seismic_enclave_server::utils::supervisorctl::reth_is_running;

// This test expects that the booter's attestation is already allowed by the upgrade operator
// This can be set up by running the test_multisig_upgrade_operator_workflow test in the enclave-contract crate
#[serial(attestation_agent)]
#[tokio::test]
async fn test_boot_share_root_key() {
    // Check the starting conditions are as expected
    if !is_sudo() {
        panic!("test_boot_share_root_key: skipped (requires sudo privileges)");
    }
    assert!(reth_is_running(), "Test startup error: Reth is not running");

    let addy = UPGRADE_MULTISIG_ADDRESS;
    // Test the booter with the canonical deployment
    let enclave_engine: AttestationEngine<KeyManager> = engine_mock_booted().await;
    let new_node_booter = Booter::mock();
    let eval_context: AttestationEvalEvidenceRequest = pub_key_eval_request();
    assert_eq!(
        seismic_enclave::request_types::Data::Raw(new_node_booter.pk().serialize().to_vec()),
        eval_context.clone().runtime_data.unwrap(),
        "test misconfigured, attestation should be of the new booter's public key"
    );
    let resp = enclave_engine
        .boot_share_root_key(ShareRootKeyRequest {
            evidence: eval_context.evidence,
            tee: eval_context.tee,
            retriever_pk: new_node_booter.pk(),
        })
        .await
        .unwrap();
    let key_plaintext = new_node_booter.process_share_response(resp).unwrap(); // erroring due to mismatch
    assert!(
        key_plaintext == [0u8; 32],
        "root key does not match expected mock value"
    );
}
