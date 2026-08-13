//! Live reth-backed registry test: the compiled bootstrap policy is live from
//! block 0 via real `eth_call` at the well-known registry address, then the
//! whole revision lifecycle of `SPEC.md` — accept a second image, withdraw
//! the first, reinstate it — runs through the authority.
//!
//! Every revision's `activePolicyHash` is the compiled hash of a committed
//! golden document, and registry state is asserted equal to that document's
//! compiled accepted set, so the sequence exercises the invariant the
//! specification states rather than a synthetic status delta.
//!
//! The node is a real `seismic-reth` dev process (auto-mining, HTTP RPC)
//! launched on a genesis built from `fixtures/reth-genesis-template.json`.
//! The template mirrors reth's committed genesis templates — the registry
//! predeploy ships the canonical runtime with empty storage — and this test
//! plays the deploy role: it compiles a golden policy document with
//! [`compile_policy`] and writes [`registry_genesis_storage`] into the
//! registry account before boot. The template's registry code is pinned to
//! [`REGISTRY_RUNTIME_CODE_HASH`], so it cannot drift from the canonical
//! `contracts/artifacts/MeasurementRegistry.json` unnoticed.
//!
//! Requires a `seismic-reth` binary: `SEISMIC_RETH_BIN`, `$PATH`, or a
//! sibling `seismic-reth` checkout's target directory. The binary is required:
//! without one the test fails, the same stance seismic-alloy takes on `sanvil`.

use std::{
    env, fs,
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use alloy::{
    network::EthereumWallet,
    primitives::{Address, B256, U256, address, keccak256},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use seismic_measurement_admission::{
    CompiledPolicy, compile_policy,
    genesis::{REGISTRY_RUNTIME_CODE_HASH, registry_genesis_storage},
};

mod common;
use common::{IMeasurementAuthorityDev, IMeasurementRegistry};

const REGISTRY: Address = address!("0x1000000000000000000000000000000000000001");
const AUTHORITY: Address = address!("0x1000000000000000000000000000000000000002");

/// Anvil dev account 0 — `MeasurementAuthorityDev.OWNER`.
const OWNER_SK: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
/// Anvil dev account 1 — funded in the template but not the authority owner.
const INTRUDER_SK: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

const STATUS_UNKNOWN: u8 = 0;
const STATUS_ACCEPTED: u8 = 1;
const STATUS_DEPRECATED: u8 = 2;

/// Fixed gas for `applyPolicyUpdate` transactions (single-ID updates fit
/// comfortably); see the estimation note at the first send site.
const APPLY_POLICY_UPDATE_GAS: u64 = 500_000;

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

/// A running dev node; the process and its scratch directory live exactly as
/// long as this guard.
struct RethNode {
    child: Child,
    dir: PathBuf,
    http_url: String,
}

impl Drop for RethNode {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// Compile one committed golden policy document.
fn compile_fixture(name: &str) -> CompiledPolicy {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/golden")
        .join(name);
    let bytes = fs::read(&path).unwrap_or_else(|error| {
        panic!("failed to read fixture {}: {error}", path.display());
    });
    compile_policy(&bytes).expect("fixture policy compiles")
}

/// Seed the template's registry account with the bootstrap document's genesis
/// storage and boot `seismic-reth` on the result.
fn launch_seeded_node(reth: &PathBuf, bootstrap: &CompiledPolicy) -> RethNode {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let template = fs::read_to_string(manifest.join("fixtures/reth-genesis-template.json"))
        .expect("genesis template");
    let mut genesis: serde_json::Value = serde_json::from_str(&template).expect("template JSON");

    let registry_account = &mut genesis["alloc"][&format!("{REGISTRY:#x}")];
    let code_hex = registry_account["code"]
        .as_str()
        .expect("registry code in template");
    let code = hex::decode(code_hex.trim_start_matches("0x")).expect("registry code hex");
    assert_eq!(
        keccak256(&code),
        REGISTRY_RUNTIME_CODE_HASH,
        "template registry code drifted from the canonical artifact \
         (contracts/artifacts/MeasurementRegistry.json)"
    );

    let storage: serde_json::Map<String, serde_json::Value> = registry_genesis_storage(bootstrap)
        .iter()
        .map(|(slot, value)| {
            (
                format!("{slot}"),
                serde_json::Value::from(format!("{value}")),
            )
        })
        .collect();
    registry_account["storage"] = serde_json::Value::Object(storage);

    let http_port = free_port();
    let dir = env::temp_dir().join(format!("measurement-admission-reth-{http_port}"));
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
    let child = Command::new(reth)
        .args(["node", "--dev", "--dev.block-max-transactions", "1"])
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

async fn wait_for_rpc(node: &RethNode) -> impl Provider + Clone + use<> {
    let provider = ProviderBuilder::new().connect_http(node.http_url.parse().unwrap());
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

fn wallet_provider(node: &RethNode, sk: &str) -> impl Provider + Clone {
    let signer: PrivateKeySigner = sk.parse().unwrap();
    ProviderBuilder::new()
        .wallet(EthereumWallet::from(signer))
        .connect_http(node.http_url.parse().unwrap())
}

/// Assert live registry state equals what `document` compiles to: the
/// accepted set decides `isAccepted` for every identity in `universe`, the
/// counters agree, and the active hash is the document's own hash. The
/// bootstrap hash is genesis's and never moves.
async fn assert_state_matches_document(
    registry: &IMeasurementRegistry::IMeasurementRegistryInstance<impl Provider + Clone>,
    document: &CompiledPolicy,
    expected_revision: u64,
    bootstrap_policy_hash: B256,
    universe: &[B256],
) {
    let accepted: Vec<B256> = document
        .admission_ids
        .iter()
        .map(|id| B256::from(*id))
        .collect();

    for id in universe {
        assert_eq!(
            registry.isAccepted(*id).call().await.unwrap(),
            accepted.contains(id),
            "{id} admission disagrees with the compiled document at revision \
             {expected_revision}"
        );
    }
    assert_eq!(
        registry.acceptedCount().call().await.unwrap(),
        U256::from(accepted.len())
    );
    assert_eq!(
        registry.activePolicyHash().call().await.unwrap(),
        document.policy_hash
    );
    assert_eq!(
        registry.policyRevision().call().await.unwrap(),
        expected_revision
    );
    assert_eq!(
        registry.bootstrapPolicyHash().call().await.unwrap(),
        bootstrap_policy_hash
    );
}

/// Apply one policy update through the authority and require it to land.
async fn apply_update(
    authority: &IMeasurementAuthorityDev::IMeasurementAuthorityDevInstance<impl Provider + Clone>,
    accept: Vec<B256>,
    deprecate: Vec<B256>,
    new_active_policy_hash: B256,
) {
    let receipt = authority
        .applyPolicyUpdate(accept, deprecate, new_active_policy_hash)
        .gas(APPLY_POLICY_UPDATE_GAS)
        .send()
        .await
        .expect("send policy update")
        .get_receipt()
        .await
        .expect("policy update receipt");
    assert!(receipt.status(), "policy update reverted");
}

#[tokio::test]
async fn genesis_policy_and_revision_lifecycle_follow_the_compiled_documents() {
    let reth = find_reth().expect(
        "no seismic-reth binary: set SEISMIC_RETH_BIN, add seismic-reth to PATH, \
         or build the sibling checkout (cargo build --bin seismic-reth)",
    );

    // The three golden documents form one revision sequence: image A founds
    // the network, image B joins the policy, image A is withdrawn, image A
    // returns.
    let image_a = compile_fixture("measurement-policy-v1.image-a.json");
    let both_images = compile_fixture("measurement-policy-v1.json");
    let image_b = compile_fixture("measurement-policy-v1.image-b.json");
    let id_a = B256::from(image_a.admission_ids[0]);
    let id_b = B256::from(image_b.admission_ids[0]);
    let universe = [id_a, id_b];
    let bootstrap_policy_hash = image_a.policy_hash;

    let node = launch_seeded_node(&reth, &image_a);
    let provider = wait_for_rpc(&node).await;
    let registry = IMeasurementRegistry::new(REGISTRY, provider.clone());

    // Revision 1, block 0: the bootstrap document is the live policy straight
    // out of genesis storage — no initialization transaction ever ran.
    assert_eq!(provider.get_block_number().await.unwrap(), 0);
    assert_state_matches_document(&registry, &image_a, 1, bootstrap_policy_hash, &universe).await;
    assert_eq!(
        registry.statusOf(id_a).call().await.unwrap(),
        STATUS_ACCEPTED
    );
    assert_eq!(
        registry.statusOf(id_b).call().await.unwrap(),
        STATUS_UNKNOWN
    );
    assert!(
        !registry
            .isAccepted(keccak256("unknown-admission-id"))
            .call()
            .await
            .unwrap()
    );

    // A non-owner sender is rejected by the authority (NotOwner), leaving the
    // registry untouched. Explicit gas on every mutation below: plain
    // eth_estimateGas is an unsigned read, for which seismic-reth zeroes
    // msg.sender, tripping the owner check during the preflight. Sender-
    // authenticated estimation exists (`seismic_estimateGas` with a signed
    // TxSeismic, via the seismic clients); fixed gas keeps this test on
    // vanilla alloy.
    let intruder = IMeasurementAuthorityDev::new(AUTHORITY, wallet_provider(&node, INTRUDER_SK));
    let receipt = intruder
        .applyPolicyUpdate(vec![id_b], vec![], both_images.policy_hash)
        .gas(APPLY_POLICY_UPDATE_GAS)
        .send()
        .await
        .expect("send non-owner update")
        .get_receipt()
        .await
        .expect("non-owner update receipt");
    assert!(!receipt.status(), "non-owner update must revert");
    assert_state_matches_document(&registry, &image_a, 1, bootstrap_policy_hash, &universe).await;

    // Revision 2: the owner accepts image B, and the active hash becomes the
    // two-image document's own hash.
    let authority = IMeasurementAuthorityDev::new(AUTHORITY, wallet_provider(&node, OWNER_SK));
    apply_update(&authority, vec![id_b], vec![], both_images.policy_hash).await;
    assert_state_matches_document(&registry, &both_images, 2, bootstrap_policy_hash, &universe)
        .await;

    // Revision 3: image A is withdrawn. It stops being admitted immediately,
    // with no node or service restart.
    apply_update(&authority, vec![], vec![id_a], image_b.policy_hash).await;
    assert_state_matches_document(&registry, &image_b, 3, bootstrap_policy_hash, &universe).await;
    assert_eq!(
        registry.statusOf(id_a).call().await.unwrap(),
        STATUS_DEPRECATED
    );

    // Revision 4: image A returns. Reinstatement is a plain accept of a
    // deprecated ID, and republishing revision 2's document reuses its hash —
    // the unchanged-hash rule only forbids repeating the *current* one.
    apply_update(&authority, vec![id_a], vec![], both_images.policy_hash).await;
    assert_state_matches_document(&registry, &both_images, 4, bootstrap_policy_hash, &universe)
        .await;
    assert_eq!(
        registry.statusOf(id_a).call().await.unwrap(),
        STATUS_ACCEPTED
    );
}
