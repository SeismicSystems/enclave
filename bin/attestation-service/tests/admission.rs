//! Reth-backed responder-admission suite, run through
//! `scripts/run_attestation_service_admission_tdx_tests.sh` on an Azure TDX
//! runner: the service's `getWrappedRootKey` gate against a real
//! `seismic-reth` dev node whose genesis storage carries the measurement
//! policy. The complement to
//! the registry-only tests in
//! `crates/measurement-admission/tests/reth_registry.rs` and to the
//! admission module's mocked unit tests: here the full live path — verified
//! vTPM evidence → admission ID → fresh finalized chain state → registry
//! verdict — decides real handshakes, and the assertions ride the wire codes
//! a joiner sees.
//!
//! - an **accepted** tuple authorizes exactly one root-key wrap (a real
//!   joiner service completes its bootstrap);
//! - a **deprecated** tuple is denied on its identity (`-32002`) by the same
//!   still-running responder — the policy is read live from the chain, never
//!   cached;
//! - an **unknown** tuple is denied on its identity (`-32002`);
//! - an unreachable (`-32003`) or **stale** (`-32003`, via a tightened
//!   policy-age bound) local reth fails closed;
//! - a local reth serving a chain the manifest does not commit to fails closed
//!   (`-32003`) and names both chains on the operator-facing node status,
//!   exercising the pinned `eth.genesis_hash` end to end.
//!
//! The genesis is generated at runtime, not committed: evidence carries the
//! runner's real PCRs, so the seeded policy is compiled either from the
//! observed values (the runner's own image is the accepted tuple) or from
//! synthetic values no real quote can match (the runner's image is the
//! unknown tuple). Two dev-miner behaviors shape the fixture: `finalized` is
//! served from block 0 but stays on the genesis block until the chain is
//! ~64 blocks deep, so the genesis timestamp is stamped to now — in
//! milliseconds, the chain's timestamp convention — to keep that view inside
//! the freshness bound; and at block 0 the gate's genesis window admits
//! unconditionally, so every rejection scenario first waits for the chain to
//! advance.
//!
//! TPM discipline is the same as the `evidence` target: quote generation
//! opens the raw single-open TPM device, so every test carries
//! `serial(attestation_evidence)` and runs its handshakes sequentially.
//!
//! Requires sudo (TPM access, and the `/run/seismic` handoff directory the
//! suite writes each network's manifest into) plus a `seismic-reth` binary
//! (`SEISMIC_RETH_BIN`, `$PATH`, or a sibling checkout's target directory).

use std::{
    collections::HashMap,
    env, fs,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use alloy::{
    eips::BlockId,
    network::EthereumWallet,
    providers::{Provider, ProviderBuilder, RootProvider},
    signers::local::PrivateKeySigner,
    sol,
};
use alloy_primitives::{Address, B256, address, keccak256};
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use seismic_attestation::{
    AttestationType, NetworkId, SeismicMeasurementPolicy, VerifiedSeismicAttestation,
    VerifyOptions, generate_evidence, verify_evidence_with_policy,
};
use seismic_attestation_rpc::AttestationRpcClient as _;
use seismic_attestation_service::{
    Args,
    api::{AdmissionChainStatus, NodeStatusRpcClient as _},
    bootstrap::build_root_key_request,
    rpc_error::RootKeyRefusal,
    utils::{init_tracing, is_sudo},
};
use seismic_custodian::Custodian;
use seismic_custodian_ipc::{
    Request,
    server::{MethodAcl, bind, serve},
};
use seismic_custodian_service::{dispatch::dispatch, state::CustodianState};
use seismic_measurement_admission::{
    AZURE_TDX_V1_PCRS, AzureTdxV1Measurements, compile_policy,
    genesis::{REGISTRY_RUNTIME_CODE_HASH, registry_genesis_storage},
};
use seismic_measurement_registry_client::{MEASUREMENT_REGISTRY_ADDRESS, MeasurementRegistry};

/// The manifest both sides of every handshake derive their network ID from.
/// The fixture is a template here: a network's identity commits to its genesis
/// block, and this suite mints a fresh genesis per test — the seeded policy and
/// the stamped timestamp both move its hash — so `eth.genesis_hash` is filled
/// in from the live node by [`install_network_manifest`].
const NETWORK_MANIFEST_TEMPLATE: &[u8] =
    include_bytes!("../../../crates/network-manifest/fixtures/network-manifest-v1.json");

/// Where the image drops the manifest and the service reads it from.
const NETWORK_MANIFEST_PATH: &str = "/run/seismic/conf/network-manifest.json";
/// A genesis hash no seeded node here can serve, so a manifest pinning it
/// names a chain the responder's local reth is not on.
const FOREIGN_GENESIS: B256 = B256::repeat_byte(0xef);

/// `MeasurementAuthorityDev` genesis predeploy (the manifest's
/// `measurements.contracts.authority`).
const AUTHORITY: Address = address!("0x1000000000000000000000000000000000000002");
/// Anvil dev account 0 — `MeasurementAuthorityDev.OWNER`, funded in the
/// genesis template.
const OWNER_SK: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
/// Fixed gas for `applyPolicyUpdate`: plain `eth_estimateGas` is an unsigned
/// read, for which seismic-reth zeroes `msg.sender`, tripping the owner check
/// during the preflight (see `reth_registry.rs` for the long version).
const APPLY_POLICY_UPDATE_GAS: u64 = 500_000;

/// Interval-mining period. The freshness gate reads the finalized view, which
/// trails `latest` by ~63 blocks in dev mode: 500ms blocks hold that view
/// ~32s old in steady state — inside the production 60s bound with headroom,
/// and past any per-test tightened bound.
const BLOCK_TIME: &str = "500ms";
/// Tightened policy-age bound for the staleness scenario, far under the ~32s
/// steady-state finalized age.
const STALE_MAX_POLICY_AGE: Duration = Duration::from_secs(3);

const NODE_STARTUP_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/// One direct handshake: a fresh quote, verification with collateral
/// fetches, and up to three chain-read attempts on the responder.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const RETRY_INTERVAL: Duration = Duration::from_secs(2);

sol! {
    #[sol(rpc)]
    interface IMeasurementAuthorityDev {
        function applyPolicyUpdate(
            bytes32[] calldata accept,
            bytes32[] calldata deprecate,
            bytes32 newActivePolicyHash
        ) external;
    }
}

/// The accepted path, and deprecation applying live: a joiner service
/// bootstraps against a responder whose registry accepts the runner's own
/// measurements (exactly one root-key wrap); the authority then deprecates
/// that admission ID on chain, and the same responder process denies the
/// next handshake.
#[serial_test::serial(attestation_evidence)]
#[tokio::test]
async fn test_accepted_tuple_wraps_once_then_deprecation_applies_live() {
    init_tracing();
    if !is_sudo() {
        panic!("test_accepted_tuple_wraps_once_then_deprecation_applies_live: requires sudo");
    }

    let pcrs = observed_pcrs().await;
    let admission_id = *AzureTdxV1Measurements::from_pcrs(&pcrs)
        .expect("quoted PCR bank carries every schema register")
        .admission_id()
        .as_b256();
    let node = launch_seeded_reth("suite-observed", &pcrs);
    let provider = wait_for_rpc(&node).await;
    let manifest = install_network_manifest(&provider).await;
    wait_past_genesis(&provider).await;

    let responder = start_service("responder", 30, None, &node.http_url, None).await;
    let joiner = start_service(
        "joiner",
        31,
        Some(vec![responder.url.clone()]),
        &node.http_url,
        None,
    )
    .await;
    // The joiner's health wait spans the attested exchange, so its return is
    // the join completing — authorized by exactly one custodian wrap.
    assert_eq!(
        responder.wrap_count.load(Ordering::SeqCst),
        1,
        "an accepted join must wrap the root key exactly once"
    );
    joiner.handle.abort();

    // Deprecate the runner's admission ID through the authority owner. The
    // responder reads the policy at the finalized block, so wait for the
    // deprecated verdict to finalize before asserting on a handshake.
    let authority = IMeasurementAuthorityDev::new(AUTHORITY, owner_provider(&node));
    let receipt = authority
        .applyPolicyUpdate(vec![], vec![admission_id], keccak256("suite revision 2"))
        .gas(APPLY_POLICY_UPDATE_GAS)
        .send()
        .await
        .expect("send deprecation")
        .get_receipt()
        .await
        .expect("deprecation receipt");
    assert!(receipt.status(), "deprecation transaction reverted");
    wait_finalized_rejects(&provider, admission_id).await;

    // Same responder process, no restart: the live chain read alone flips
    // the verdict, and the denied handshake never reaches the custodian.
    let denied = request_root_key(&responder.url, &manifest).await;
    assert_eq!(
        denial_refusal(denied),
        RootKeyRefusal::RequesterIdentityNotAccepted
    );
    assert_eq!(
        responder.wrap_count.load(Ordering::SeqCst),
        1,
        "a denied handshake must not wrap the root key"
    );
    assert_eq!(
        responder
            .client
            .health_check()
            .await
            .expect("responder still serving after the denial"),
        "OK"
    );
    // A denial on the requester's identity says nothing about this node's own
    // chain, which is the pinned one throughout.
    assert_eq!(
        responder
            .client
            .get_admission_chain_status()
            .await
            .expect("responder serves its admission chain status"),
        AdmissionChainStatus::Matches {
            genesis: genesis_hash(&provider).await
        }
    );
    responder.handle.abort();
}

/// A cryptographically valid guest whose tuple the registry never accepted
/// is denied; killing the responder's reth then fails closed as temporarily
/// unavailable — the same responder cannot decide without its chain.
#[serial_test::serial(attestation_evidence)]
#[tokio::test]
async fn test_unknown_tuple_is_denied_and_reth_outage_fails_closed() {
    init_tracing();
    if !is_sudo() {
        panic!("test_unknown_tuple_is_denied_and_reth_outage_fails_closed: requires sudo");
    }

    // Synthetic policy: real quotes carry the runner's PCRs, which can never
    // match these values, so the runner's admission ID is unknown on chain.
    let mut node = launch_seeded_reth("suite-synthetic", &synthetic_pcrs());
    let provider = wait_for_rpc(&node).await;
    let manifest = install_network_manifest(&provider).await;
    wait_past_genesis(&provider).await;

    let responder = start_service("responder", 32, None, &node.http_url, None).await;
    let denied = request_root_key(&responder.url, &manifest).await;
    assert_eq!(
        denial_refusal(denied),
        RootKeyRefusal::RequesterIdentityNotAccepted
    );
    assert_eq!(responder.wrap_count.load(Ordering::SeqCst), 0);

    node.stop();
    let unavailable = request_root_key(&responder.url, &manifest).await;
    assert_eq!(
        denial_refusal(unavailable),
        RootKeyRefusal::ResponderUnavailable
    );
    assert_eq!(responder.wrap_count.load(Ordering::SeqCst), 0);
    responder.handle.abort();
}

/// A responder whose finalized policy view is older than its bound refuses
/// to decide. The registry would accept this tuple (the policy is compiled
/// from the runner's observed PCRs) and the chain is alive and mining — the
/// tightened bound alone turns the answer into temporarily unavailable.
#[serial_test::serial(attestation_evidence)]
#[tokio::test]
async fn test_stale_policy_view_fails_closed() {
    init_tracing();
    if !is_sudo() {
        panic!("test_stale_policy_view_fails_closed: requires sudo");
    }

    let pcrs = observed_pcrs().await;
    let node = launch_seeded_reth("suite-observed", &pcrs);
    let provider = wait_for_rpc(&node).await;
    let manifest = install_network_manifest(&provider).await;
    wait_past_genesis(&provider).await;

    let responder = start_service(
        "responder",
        33,
        None,
        &node.http_url,
        Some(STALE_MAX_POLICY_AGE),
    )
    .await;
    // Let the finalized view age well past the bound (it only grows from
    // here: the genesis stamp recedes until the ~64-block flip, after which
    // the view sits at the ~32s steady-state lag), so every retry attempt
    // within the handshake sees a stale chain.
    wait_finalized_older_than(&provider, STALE_MAX_POLICY_AGE * 3).await;

    let stale = request_root_key(&responder.url, &manifest).await;
    assert_eq!(denial_refusal(stale), RootKeyRefusal::ResponderUnavailable);
    assert_eq!(responder.wrap_count.load(Ordering::SeqCst), 0);
    responder.handle.abort();
}

/// A responder reading its policy off a chain its manifest does not commit to
/// refuses to decide. Everything else is the accepted path — the node is
/// seeded from the runner's observed PCRs, mining, and fresh — so the pinned
/// genesis alone turns the answer into temporarily unavailable, and it does so
/// on the manifest field the service reads at startup.
#[serial_test::serial(attestation_evidence)]
#[tokio::test]
async fn test_foreign_pinned_genesis_fails_closed() {
    init_tracing();
    if !is_sudo() {
        panic!("test_foreign_pinned_genesis_fails_closed: requires sudo");
    }

    let pcrs = observed_pcrs().await;
    let node = launch_seeded_reth("suite-observed", &pcrs);
    let provider = wait_for_rpc(&node).await;
    let manifest = install_manifest_pinning(FOREIGN_GENESIS);
    // Past genesis the gate reads block 0 through a query of its own, the
    // branch a forged chain with a progressing head aims at.
    wait_past_genesis(&provider).await;

    let responder = start_service("responder", 34, None, &node.http_url, None).await;
    let unavailable = request_root_key(&responder.url, &manifest).await;
    assert_eq!(
        denial_refusal(unavailable),
        RootKeyRefusal::ResponderUnavailable
    );
    assert_eq!(responder.wrap_count.load(Ordering::SeqCst), 0);
    // The joiner is told only that this responder could not decide; the
    // operator who can repair it is told which two chains disagree, on the
    // status surface, while `healthCheck` still reports the service itself up.
    assert_eq!(
        responder
            .client
            .health_check()
            .await
            .expect("responder still serving"),
        "OK"
    );
    assert_eq!(
        responder
            .client
            .get_admission_chain_status()
            .await
            .expect("responder serves its admission chain status"),
        AdmissionChainStatus::GenesisMismatch {
            expected: FOREIGN_GENESIS,
            found: genesis_hash(&provider).await,
        }
    );
    responder.handle.abort();
}

/// Quote the local vTPM once and return the verified PCR bank — the values
/// the fixture policy pins as the network-accepted tuple. The binding is
/// self-chosen and self-verified; only the PCR bank matters here.
async fn observed_pcrs() -> HashMap<u32, [u8; 32]> {
    let binding = [0x42u8; 64];
    let evidence = generate_evidence(AttestationType::AzureTdx, binding)
        .expect("vTPM quote (needs sudo and a free TPM device)");
    let verified = verify_evidence_with_policy(
        evidence,
        binding,
        SeismicMeasurementPolicy::dangerously_accept_any_for_testing(AttestationType::AzureTdx),
        VerifyOptions::default(),
    )
    .await
    .expect("verifying our own quote");
    match verified {
        VerifiedSeismicAttestation::AzureTdx(azure) => azure
            .guest_measurements
            .pcrs
            .iter()
            .map(|(index, value)| (*index, *value))
            .collect(),
        other => panic!("expected an Azure TDX attestation, got {other:?}"),
    }
}

/// A full schema bank of values no real quote can carry.
fn synthetic_pcrs() -> HashMap<u32, [u8; 32]> {
    HashMap::from([(4, [0xA4u8; 32]), (9, [0xA9u8; 32]), (11, [0xB1u8; 32])])
}

/// Compile a one-record policy from `pcrs`, seed the committed genesis
/// template's registry account with its storage, stamp the genesis timestamp
/// to now (milliseconds, the chain's convention — this is what keeps the
/// dev miner's genesis-pinned finalized view inside the freshness bound),
/// and boot `seismic-reth` on the result.
fn launch_seeded_reth(measurement_id: &str, pcrs: &HashMap<u32, [u8; 32]>) -> RethNode {
    let policy_measurements: serde_json::Map<String, serde_json::Value> = AZURE_TDX_V1_PCRS
        .iter()
        .map(|index| {
            (
                format!("pcr{index}"),
                serde_json::json!({ "expected_any": [hex::encode(pcrs[index])] }),
            )
        })
        .collect();
    let policy_doc = serde_json::json!([{
        "measurement_id": measurement_id,
        "attestation_type": "azure-tdx",
        "measurements": policy_measurements,
    }]);
    let compiled = compile_policy(&serde_json::to_vec(&policy_doc).expect("serialize policy"))
        .expect("suite policy document compiles");

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let template_path =
        manifest_dir.join("../../crates/measurement-admission/fixtures/reth-genesis-template.json");
    let template = fs::read_to_string(&template_path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", template_path.display()));
    let mut genesis: serde_json::Value =
        serde_json::from_str(&template).expect("genesis template JSON");

    let registry_account = &mut genesis["alloc"][&format!("{MEASUREMENT_REGISTRY_ADDRESS:#x}")];
    let code = hex::decode(
        registry_account["code"]
            .as_str()
            .expect("registry code in template")
            .trim_start_matches("0x"),
    )
    .expect("registry code hex");
    assert_eq!(
        keccak256(&code),
        REGISTRY_RUNTIME_CODE_HASH,
        "template registry code drifted from the canonical artifact"
    );
    let storage: serde_json::Map<String, serde_json::Value> = registry_genesis_storage(&compiled)
        .iter()
        .map(|(slot, value)| {
            (
                format!("{slot}"),
                serde_json::Value::from(format!("{value}")),
            )
        })
        .collect();
    registry_account["storage"] = serde_json::Value::Object(storage);
    genesis["timestamp"] = serde_json::Value::from(format!("{:#x}", now_millis()));

    let http_port = free_port();
    let dir = env::temp_dir().join(format!("attestation-admission-reth-{http_port}"));
    fs::create_dir_all(&dir).expect("create node scratch dir");
    let genesis_path = dir.join("genesis.json");
    fs::write(
        &genesis_path,
        serde_json::to_string_pretty(&genesis).unwrap(),
    )
    .expect("write genesis");

    // --seismic.purpose-keys-source built-in: the default source waits on the
    // custodian socket and aborts when absent. --ipcdisable and explicit
    // authrpc/p2p ports: their defaults are global (one path/port per chain
    // ID), so concurrent test nodes would collide.
    let child = Command::new(find_reth().expect(
        "no seismic-reth binary: set SEISMIC_RETH_BIN, add seismic-reth to PATH, \
         or build the sibling checkout (cargo build --bin seismic-reth)",
    ))
    .args(["node", "--dev", "--dev.block-time", BLOCK_TIME])
    .args(["--chain", genesis_path.to_str().unwrap()])
    .args(["--datadir", dir.join("data").to_str().unwrap()])
    .args([
        "--http",
        "--http.addr",
        "127.0.0.1",
        "--http.port",
        &http_port.to_string(),
    ])
    .args(["--authrpc.port", &free_port().to_string()])
    .args(["--ipcdisable", "--port", "0", "--disable-discovery"])
    .args(["--log.file.directory", dir.join("logs").to_str().unwrap()])
    .args(["--seismic.purpose-keys-source", "built-in"])
    .stdout(Stdio::null())
    .stderr(Stdio::from(
        fs::File::create(dir.join("reth.stderr")).expect("stderr log"),
    ))
    .spawn()
    .expect("spawn seismic-reth");

    RethNode {
        child,
        dir,
        http_url: format!("http://127.0.0.1:{http_port}"),
    }
}

fn find_reth() -> Option<PathBuf> {
    if let Ok(explicit) = env::var("SEISMIC_RETH_BIN") {
        let explicit = PathBuf::from(explicit);
        assert!(
            explicit.is_file(),
            "SEISMIC_RETH_BIN points at {}, which is not a file",
            explicit.display()
        );
        return Some(explicit);
    }
    if let Some(paths) = env::var_os("PATH") {
        for dir in env::split_paths(&paths) {
            let candidate = dir.join("seismic-reth");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    // Workspace-sibling checkout (enclave/ and seismic-reth/ share a parent).
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for profile in ["debug", "release"] {
        let candidate = manifest
            .join("../../../seismic-reth/target")
            .join(profile)
            .join("seismic-reth");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .unwrap()
        .port()
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_millis() as u64
}

/// A running dev node; the process and its scratch directory live exactly as
/// long as this value.
struct RethNode {
    child: Child,
    dir: PathBuf,
    http_url: String,
}

impl RethNode {
    /// Kill the node while keeping the value alive — the chain-outage
    /// scenario takes reth away from a responder that keeps serving.
    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for RethNode {
    fn drop(&mut self) {
        self.stop();
        let _ = fs::remove_dir_all(&self.dir);
    }
}

async fn wait_for_rpc(node: &RethNode) -> RootProvider {
    let provider = RootProvider::new_http(node.http_url.parse().expect("node HTTP URL"));
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match provider.get_chain_id().await {
            Ok(id) => {
                assert_eq!(id, 5124, "node came up on an unexpected chain");
                return provider;
            }
            Err(_) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(250)).await
            }
            Err(e) => panic!(
                "seismic-reth RPC not ready within 30s: {e} (see {})",
                node.dir.join("reth.stderr").display()
            ),
        }
    }
}

/// Render the manifest for the chain `provider` serves, drop it at the
/// service's handoff path, and return the exact bytes written.
///
/// Pinning `eth.genesis_hash` to this node's block 0 is what lets the
/// responder's admission read its registry at all: the gate refuses to answer
/// on a chain the manifest does not commit to. `network_id` is SHA-256 over the
/// file's bytes, so callers must hash the returned bytes rather than
/// re-serialize the manifest.
async fn install_network_manifest(provider: &RootProvider) -> Vec<u8> {
    install_manifest_pinning(genesis_hash(provider).await)
}

/// The block-0 hash the live dev node serves: the chain a status read finds,
/// whether or not the installed manifest pins it.
async fn genesis_hash(provider: &RootProvider) -> B256 {
    provider
        .get_block_by_number(alloy::eips::BlockNumberOrTag::Earliest)
        .await
        .expect("genesis query")
        .expect("dev node serves block 0")
        .header
        .hash
}

/// Render the manifest that pins `genesis_hash`, drop it at the service's
/// handoff path, and return the exact bytes written.
fn install_manifest_pinning(genesis_hash: B256) -> Vec<u8> {
    let mut manifest: serde_json::Value =
        serde_json::from_slice(NETWORK_MANIFEST_TEMPLATE).expect("manifest template JSON");
    manifest["eth"]["genesis_hash"] = serde_json::Value::from(format!("{genesis_hash:#x}"));
    let bytes = serde_json::to_vec_pretty(&manifest).expect("serialize manifest");
    fs::write(NETWORK_MANIFEST_PATH, &bytes)
        .unwrap_or_else(|e| panic!("writing {NETWORK_MANIFEST_PATH}: {e}"));
    bytes
}

/// Wait until `latest` is past block 0: the admission gate's genesis window
/// admits unconditionally at block 0, so every rejection scenario starts
/// after the chain has advanced.
async fn wait_past_genesis(provider: &RootProvider) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let number = provider.get_block_number().await.expect("latest number");
        if number > 0 {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "dev node mined no block within 30s"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Wait until the registry's *finalized* view rejects `admission_id` — the
/// view admission decisions read, trailing `latest` by ~63 blocks in dev
/// mode, so a deprecation takes ~32s at 500ms blocks to become decisive.
async fn wait_finalized_rejects(provider: &RootProvider, admission_id: B256) {
    let registry = MeasurementRegistry::new(MEASUREMENT_REGISTRY_ADDRESS, provider.clone());
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let accepted = registry
            .isAccepted(admission_id)
            .block(BlockId::finalized())
            .call()
            .await
            .expect("isAccepted at the finalized tag");
        if !accepted {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "deprecation did not reach the finalized view within 120s"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Wait until the finalized block's timestamp is at least `age` behind the
/// wall clock.
async fn wait_finalized_older_than(provider: &RootProvider, age: Duration) {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let finalized = provider
            .get_block_by_number(alloy::eips::BlockNumberOrTag::Finalized)
            .await
            .expect("finalized query")
            .expect("dev node serves a finalized block");
        let observed =
            Duration::from_millis(now_millis().saturating_sub(finalized.header.inner.timestamp));
        if observed >= age {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "finalized view did not age past {age:?} within 60s"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// One custodian/attestation-service pair under test, with a counter over
/// the custodian's `WrapRootKey` dispatches — each count is one root-key
/// release this responder authorized.
struct ServiceNode {
    /// Owns the runtime directory (custodian socket, LUKS keyfile path).
    _runtime: tempfile::TempDir,
    url: String,
    client: HttpClient,
    handle: tokio::task::JoinHandle<anyhow::Result<()>>,
    wrap_count: Arc<AtomicUsize>,
}

/// Start a custodian/attestation-service pair against `reth_rpc_url` and
/// wait until its RPC listener is healthy.
///
/// `peers: None` starts a responder (genesis custodian, fresh root key);
/// `Some(urls)` starts a joiner whose custodian acquires the root key from
/// those peers, so returning implies the join completed. `n` offsets the
/// HTTP port; keep offsets distinct across tests — they share one process,
/// and a just-aborted listener may still hold its port.
async fn start_service(
    label: &'static str,
    n: u16,
    peers: Option<Vec<String>>,
    reth_rpc_url: &str,
    max_policy_age: Option<Duration>,
) -> ServiceNode {
    let runtime = tempfile::tempdir().expect("create service runtime directory");
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
    let wrap_count = spawn_counting_custodian(state, &socket);

    let args = Args {
        ip: "0.0.0.0".to_string(),
        port: 7878 + n,
        peers: peers.unwrap_or_default(),
        custodian_socket: socket,
        reth_rpc_url: reth_rpc_url.parse().expect("valid reth RPC URL"),
        max_policy_age,
    };
    let url = format!("http://localhost:{}", args.port);
    let mut handle = tokio::spawn(args.start());
    let client = HttpClientBuilder::default()
        .build(url.clone())
        .unwrap_or_else(|e| panic!("create {label} client: {e}"));
    wait_for_health(&client, label, &mut handle).await;

    ServiceNode {
        _runtime: runtime,
        url,
        client,
        handle,
        wrap_count,
    }
}

/// Serve `state` over a custodian socket from a dedicated thread — the same
/// transport and dispatch the standalone `seismic-custodian-service` binary
/// runs — counting `WrapRootKey` requests on the way through.
fn spawn_counting_custodian(state: CustodianState, socket: &Path) -> Arc<AtomicUsize> {
    let wrap_count = Arc::new(AtomicUsize::new(0));
    let counter = wrap_count.clone();
    let listener = bind(socket).expect("bind custodian socket");
    std::thread::spawn(move || {
        serve(listener, MethodAcl::own_uid_only(), move |request| {
            if matches!(request, Request::WrapRootKey { .. }) {
                counter.fetch_add(1, Ordering::SeqCst);
            }
            dispatch(&state, request)
        })
    });
    wrap_count
}

/// Wait until the server's `healthCheck` RPC returns `OK`.
///
/// A joining server binds its RPC listener after fetching and installing the
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

/// One direct requester handshake: an attested `RootKeyRequest` over the
/// runner's real quote, POSTed to `responder_url`. The denial scenarios ride
/// this instead of a joiner service, whose fetch loop would retry denials
/// forever. The ephemeral key is fixed — no response is ever unwrapped here.
async fn request_root_key(
    responder_url: &str,
    manifest: &[u8],
) -> Result<Vec<u8>, jsonrpsee::core::client::Error> {
    let eph_sk = secp256k1::SecretKey::from_slice(&[0x42u8; 32]).expect("valid test secret key");
    let eph_pk = secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &eph_sk);
    let request = build_root_key_request(
        &NetworkId::from_manifest_bytes(manifest),
        &eph_pk,
        AttestationType::AzureTdx,
    )
    .expect("build attested root-key request");
    let client = HttpClientBuilder::default()
        .request_timeout(HANDSHAKE_TIMEOUT)
        .build(responder_url)
        .expect("create handshake client");
    client
        .get_wrapped_root_key(serde_json::to_vec(&request).expect("serialize root-key request"))
        .await
}

/// The JSON-RPC error code a failed handshake surfaced.
/// The refusal a denied handshake came back with, read off the wire the way a
/// joining node reads it.
fn denial_refusal(result: Result<Vec<u8>, jsonrpsee::core::client::Error>) -> RootKeyRefusal {
    match result {
        Err(jsonrpsee::core::client::Error::Call(error)) => RootKeyRefusal::from_code(error.code())
            .unwrap_or_else(|| {
                panic!(
                    "handshake must be refused with a root-key code, got {}",
                    error.code()
                )
            }),
        Ok(_) => panic!("handshake must be denied, but a wrapped root key came back"),
        Err(other) => panic!("handshake must fail with a JSON-RPC call error, got: {other}"),
    }
}

fn owner_provider(node: &RethNode) -> impl Provider + Clone {
    let signer: PrivateKeySigner = OWNER_SK.parse().unwrap();
    ProviderBuilder::new()
        .wallet(EthereumWallet::from(signer))
        .connect_http(node.http_url.parse().unwrap())
}
