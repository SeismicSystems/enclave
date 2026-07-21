//! Live-TEE integration coverage run through
//! `scripts/run_integration_tests.sh`. The script prepares the runtime
//! manifest, frees the TPM, and executes these tests with the required
//! privileges.
//!
//! Quote generation opens the raw TPM device, which the kernel hands to one
//! process at a time (az-cvm-vtpm hardcodes tss-esapi's default TCTI,
//! `/dev/tpm0`; only `/dev/tpmrm0` multiplexes). Evidence operations must
//! therefore never overlap, and each level of concurrency has its own guard:
//! the script keeps other processes off the device, the shared
//! `serial(attestation_evidence)` key runs these tests one at a time within
//! this binary, and each test starts its nodes sequentially so a single test
//! never has two quote operations in flight. Relaxations are tracked
//! upstream (kinvolk/azure-cvm-tooling#92/#93, flashbots/attested-tls#72/#73);
//! `seismic_attestation::generate_evidence`'s docs carry the cost model.

use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use crate::utils::{get_args, spawn_custodian};
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use seismic_attestation::{
    AttestationType, NetworkId, NetworkManifestV1, SeismicMeasurementPolicy,
    bindings::{binding64_from_digest32, tx_io_binding},
    verify_evidence,
};
use seismic_attestation_rpc::{AttestationRpcClient as _, TxIoAttestationResponse};
use seismic_attestation_service::{
    api::NodeStatusRpcClient as _,
    utils::{init_tracing, is_sudo},
};
use seismic_custodian::Custodian;
use seismic_custodian_ipc::CustodianClient;
use seismic_custodian_service::state::CustodianState;

// The server reads its manifest through the same fixed `/run/seismic` handoff
// used in production, which keeps these tests covering the tdx-init →
// attestation-service startup contract. This fixture is the manifest trusted by the
// relying client; the test script installs the same fixture for the server, and
// evidence verification confirms that both sides use the same network ID.
const EXPECTED_NETWORK_MANIFEST: &[u8] =
    include_bytes!("../../../../crates/network-manifest/fixtures/network-manifest-v1.json");
const NODE_STARTUP_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const EVIDENCE_RPC_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const RETRY_INTERVAL: Duration = Duration::from_secs(2);

/// The two-node bootstrap exchange: a genesis custodian/attestation-service
/// pair plus one joiner, over real sockets with real quote generation and
/// verification. The joiner's health wait spans the attested wrapped-root-key
/// exchange, so its return is the join completing; asserts the join's
/// observable effects — the LUKS keyfile handoff and identical purpose keys
/// read from each custodian's socket.
#[serial_test::serial(attestation_evidence)]
#[tokio::test]
async fn test_two_node_root_key_bootstrap() {
    init_tracing();
    if !is_sudo() {
        panic!("test_two_node_root_key_bootstrap: skipped (requires sudo privileges)");
    }

    let genesis = start_node("genesis node", 0, None).await;
    let joiner = start_node("joining node", 1, Some(vec![genesis.url.clone()])).await;

    // The bootstrap installed the root key in the joiner's custodian, which
    // wrote the LUKS keyfile handoff as part of that transition.
    let luks_metadata = std::fs::metadata(joiner.runtime.path().join("luks-keys"))
        .expect("joining custodian wrote its LUKS keyfile");
    assert_eq!(luks_metadata.len(), 64);

    // Both custodians hold the same root key now, so every purpose key they
    // derive matches. Asked straight over each custodian's own socket — the
    // key-holding boundary reth itself fetches from.
    let keys1 = purpose_keys(&genesis.socket, 0).await;
    let keys2 = purpose_keys(&joiner.socket, 0).await;
    assert_eq!(keys1, keys2);

    genesis.handle.abort();
    joiner.handle.abort();
}

/// The relying-party path for the network's tx-io key advertisement, against
/// a single genesis pair: what a wallet/SDK runs before encrypting to
/// `tx_io_pk`. The client fetches `getTxIoAttestationEvidence`, derives the
/// expected binding independently from its own trusted manifest copy, and
/// verifies the evidence through `seismic-attestation`; the same evidence
/// must fail against a wrong-epoch binding and as a tampered document.
#[serial_test::serial(attestation_evidence)]
#[tokio::test]
async fn test_tx_io_evidence_relying_party() {
    init_tracing();
    if !is_sudo() {
        panic!("test_tx_io_evidence_relying_party: skipped (requires sudo privileges)");
    }

    let node = start_node("genesis node", 20, None).await;

    let epoch = 0;
    let response = get_tx_io_attestation_evidence(&node.client, epoch).await;
    assert_eq!(response.epoch, epoch);
    // The advertised key is the custodian's own, per its socket.
    assert_eq!(response.tx_io_pk.serialize(), tx_io_pk(&node).await);

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

    node.handle.abort();
}

/// The N=4 companion to [`test_two_node_root_key_bootstrap`]: one
/// genesis custodian/attestation-service pair plus three joining pairs, each
/// with its own socket, LUKS-key path, and HTTP port. Arrows show root-key
/// flow, responder to requester:
///
/// ```text
/// genesis ----> joiner a ----> joiner c
///    |
///    +--------> joiner b
/// ```
///
/// So the same responder serves repeat joins (genesis -> a, b) and the root
/// key travels onward through an already-bootstrapped, non-genesis node
/// (a -> c). Nodes come up sequentially — each health wait spans the full
/// attested exchange — so quote generation never runs concurrently on the
/// runner's single vTPM (all four logical nodes legitimately share its one
/// measured image).
///
/// Covers the process boundary, requester-secret retention, IPC, and N=4
/// root-key distribution; image assembly, systemd, LUKS devices, separate
/// vTPMs, and deploy tooling are deliberately out of scope.
#[serial_test::serial(attestation_evidence)]
#[tokio::test]
async fn test_four_node_root_key_distribution() {
    init_tracing();
    if !is_sudo() {
        panic!("test_four_node_root_key_distribution: skipped (requires sudo privileges)");
    }

    let genesis = start_node("genesis node", 10, None).await;
    let joiner_a = start_node("joiner a", 11, Some(vec![genesis.url.clone()])).await;
    let joiner_b = start_node("joiner b", 12, Some(vec![genesis.url.clone()])).await;
    let joiner_c = start_node("joiner c", 13, Some(vec![joiner_a.url.clone()])).await;
    let nodes = [genesis, joiner_a, joiner_b, joiner_c];

    // Every join completed: each joining custodian installed the root key and
    // wrote the LUKS keyfile handoff as part of that transition.
    for joiner in &nodes[1..] {
        let luks_metadata = std::fs::metadata(joiner.runtime.path().join("luks-keys"))
            .unwrap_or_else(|e| panic!("{} wrote no LUKS keyfile: {e}", joiner.label));
        assert_eq!(
            luks_metadata.len(),
            64,
            "{} LUKS keyfile size",
            joiner.label
        );
    }

    // All four custodians derive the same tx_io_pk, asked directly over each
    // custodian's own socket rather than through the attestation service.
    let genesis_tx_io_pk = tx_io_pk(&nodes[0]).await;
    for joiner in &nodes[1..] {
        assert_eq!(
            tx_io_pk(joiner).await,
            genesis_tx_io_pk,
            "{} derived a different tx_io_pk than the genesis node",
            joiner.label
        );
    }

    for node in &nodes {
        node.handle.abort();
    }
}

/// The bootstrap path uses the same intentionally temporary permissive policy.
/// This test is about verifier ownership and transcript integrity; production
/// measurement admission is covered by the separately tracked on-chain policy.
fn test_measurement_policy() -> SeismicMeasurementPolicy {
    SeismicMeasurementPolicy::dangerously_accept_any_for_testing(AttestationType::AzureTdx)
}

/// A node's derived purpose keys as raw bytes, for cross-node equality
/// assertions. Test-only: production callers never hold all three at once.
#[derive(Debug, PartialEq)]
struct PurposeKeyBytes {
    tx_io_sk: [u8; 32],
    tx_io_pk: [u8; 33],
    rng_ikm: [u8; 64],
    snapshot_key: [u8; 32],
}

/// Fetch a node's purpose keys at `epoch` straight from its custodian socket.
async fn purpose_keys(socket: &Path, epoch: u64) -> PurposeKeyBytes {
    let mut custodian = CustodianClient::connect(socket)
        .await
        .expect("connect to custodian socket");
    let tx_io = custodian
        .get_tx_io_keypair(epoch)
        .await
        .expect("fetch tx-io keypair");
    let rng = custodian.get_rng_ikm(epoch).await.expect("fetch rng ikm");
    let snapshot = custodian
        .get_snapshot_key(epoch)
        .await
        .expect("fetch snapshot key");
    PurposeKeyBytes {
        tx_io_sk: tx_io.sk,
        tx_io_pk: tx_io.pk,
        rng_ikm: rng.ikm,
        snapshot_key: snapshot.key,
    }
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

/// One logical node under test: the custodian/attestation-service process
/// pair over a real socket, with its own runtime directory and HTTP port.
struct NodePair {
    label: &'static str,
    runtime: tempfile::TempDir,
    socket: PathBuf,
    url: String,
    client: HttpClient,
    handle: tokio::task::JoinHandle<anyhow::Result<()>>,
}

/// Start a node's process pair and wait until its RPC listener is healthy.
///
/// `peers: None` starts the genesis node (fresh root key); `Some(urls)`
/// starts a joiner whose custodian acquires the root key from those peers, so
/// returning implies the join completed. `n` offsets the HTTP port; keep
/// offsets distinct across tests — they share one process, and a just-aborted
/// listener may still hold its port.
async fn start_node(label: &'static str, n: u16, peers: Option<Vec<String>>) -> NodePair {
    let runtime = tempfile::tempdir().expect("create node runtime directory");
    let socket = runtime.path().join("custodian.sock");
    let luks_keyfile = runtime.path().join("luks-keys");
    let state = if peers.is_none() {
        CustodianState::new_with_root_key(
            Custodian::new_as_genesis().expect("generate genesis root key"),
            luks_keyfile,
        )
        .expect("construct genesis custodian")
    } else {
        CustodianState::new_awaiting_root_key(luks_keyfile)
    };
    spawn_custodian(state, &socket);

    let args = get_args(n, peers.unwrap_or_default(), socket.clone());
    let url = format!("http://localhost:{}", args.port);
    let mut handle = tokio::spawn(args.start());
    let client = HttpClientBuilder::default()
        .build(url.clone())
        .unwrap_or_else(|e| panic!("create {label} client: {e}"));
    wait_for_health(&client, label, &mut handle).await;

    NodePair {
        label,
        runtime,
        socket,
        url,
        client,
        handle,
    }
}

/// Fetch a node's `tx_io_pk` at epoch 0 straight from its custodian socket.
async fn tx_io_pk(node: &NodePair) -> [u8; 33] {
    let mut custodian = CustodianClient::connect(&node.socket)
        .await
        .unwrap_or_else(|e| panic!("connect to {} custodian: {e}", node.label));
    custodian
        .get_tx_io_public_key(0)
        .await
        .unwrap_or_else(|e| panic!("fetch {} tx_io_pk: {e}", node.label))
        .pk
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
