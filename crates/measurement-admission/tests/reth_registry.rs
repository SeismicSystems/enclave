//! Live reth-backed registry test: the compiled fixture policy is live from
//! block 0 via real `eth_call` at the well-known registry address, then an
//! admission ID is deprecated and reinstated through the authority.
//!
//! The node is a real `seismic-reth` dev process (auto-mining, HTTP RPC)
//! launched on a genesis built from `fixtures/reth-genesis-template.json`.
//! The template mirrors reth's committed genesis templates — the registry
//! predeploy ships the canonical runtime with empty storage — and this test
//! plays the deploy role: it compiles `fixtures/golden/measurement-policy-v1.json`
//! with [`compile_policy`] and writes [`registry_genesis_storage`] into the
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
    compile_policy,
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

/// Compile the fixture policy, seed the template's registry account with the
/// resulting genesis storage, and boot `seismic-reth` on the result.
fn launch_seeded_node(reth: &PathBuf) -> (RethNode, Vec<B256>, B256) {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let policy_bytes = fs::read(manifest.join("fixtures/golden/measurement-policy-v1.json"))
        .expect("fixture policy");
    let compiled = compile_policy(&policy_bytes).expect("fixture policy compiles");

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

    let node = RethNode {
        child,
        dir,
        http_url: format!("http://127.0.0.1:{http_port}"),
    };
    (node, compiled.admission_ids, compiled.policy_hash)
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

#[tokio::test]
async fn registry_live_from_block_0_and_authority_lifecycle() {
    let reth = find_reth().expect(
        "no seismic-reth binary: set SEISMIC_RETH_BIN, add seismic-reth to PATH, \
         or build the sibling checkout (cargo build --bin seismic-reth)",
    );

    let (node, admission_ids, policy_hash) = launch_seeded_node(&reth);
    let provider = wait_for_rpc(&node).await;
    let registry = IMeasurementRegistry::new(REGISTRY, provider.clone());

    // Block 0: every compiled admission ID is Accepted, the counters and both
    // policy hashes come straight from the compiled document — no init
    // transaction ever ran.
    assert_eq!(provider.get_block_number().await.unwrap(), 0);
    for id in &admission_ids {
        assert!(
            registry.isAccepted(*id).call().await.unwrap(),
            "{id} not accepted at genesis"
        );
        assert_eq!(
            registry.statusOf(*id).call().await.unwrap(),
            STATUS_ACCEPTED
        );
    }
    assert!(
        !registry
            .isAccepted(keccak256("unknown-admission-id"))
            .call()
            .await
            .unwrap()
    );
    assert_eq!(registry.policyRevision().call().await.unwrap(), 1);
    assert_eq!(
        registry.acceptedCount().call().await.unwrap(),
        U256::from(admission_ids.len())
    );
    assert_eq!(
        registry.bootstrapPolicyHash().call().await.unwrap(),
        policy_hash
    );
    assert_eq!(
        registry.activePolicyHash().call().await.unwrap(),
        policy_hash
    );

    // A non-owner sender is rejected by the authority (NotOwner), leaving the
    // registry untouched. Explicit gas on every mutation below: plain
    // eth_estimateGas is an unsigned read, for which seismic-reth zeroes
    // msg.sender, tripping the owner check during the preflight. Sender-
    // authenticated estimation exists (`seismic_estimateGas` with a signed
    // TxSeismic, via the seismic clients); fixed gas keeps this test on
    // vanilla alloy.
    let intruder = IMeasurementAuthorityDev::new(AUTHORITY, wallet_provider(&node, INTRUDER_SK));
    let victim = admission_ids[0];
    let revision_2_hash = keccak256("measurement-policy revision 2");
    let receipt = intruder
        .applyPolicyUpdate(vec![], vec![victim], revision_2_hash)
        .gas(APPLY_POLICY_UPDATE_GAS)
        .send()
        .await
        .expect("send non-owner update")
        .get_receipt()
        .await
        .expect("non-owner update receipt");
    assert!(!receipt.status(), "non-owner update must revert");
    assert!(registry.isAccepted(victim).call().await.unwrap());

    // Owner deprecates one ID: it stops being accepted without a node or
    // service restart, the revision advances, and only activePolicyHash moves.
    let authority = IMeasurementAuthorityDev::new(AUTHORITY, wallet_provider(&node, OWNER_SK));
    let receipt = authority
        .applyPolicyUpdate(vec![], vec![victim], revision_2_hash)
        .gas(APPLY_POLICY_UPDATE_GAS)
        .send()
        .await
        .expect("send deprecation")
        .get_receipt()
        .await
        .expect("deprecation receipt");
    assert!(receipt.status(), "deprecation transaction reverted");

    assert!(!registry.isAccepted(victim).call().await.unwrap());
    assert_eq!(
        registry.statusOf(victim).call().await.unwrap(),
        STATUS_DEPRECATED
    );
    assert_eq!(registry.policyRevision().call().await.unwrap(), 2);
    assert_eq!(
        registry.acceptedCount().call().await.unwrap(),
        U256::from(admission_ids.len() - 1)
    );
    assert_eq!(
        registry.activePolicyHash().call().await.unwrap(),
        revision_2_hash
    );
    assert_eq!(
        registry.bootstrapPolicyHash().call().await.unwrap(),
        policy_hash
    );

    // Reinstatement is a fresh accept of the deprecated ID under a third
    // revision; the genesis bootstrap hash still never moves.
    let revision_3_hash = keccak256("measurement-policy revision 3");
    let receipt = authority
        .applyPolicyUpdate(vec![victim], vec![], revision_3_hash)
        .gas(APPLY_POLICY_UPDATE_GAS)
        .send()
        .await
        .expect("send reinstatement")
        .get_receipt()
        .await
        .expect("reinstatement receipt");
    assert!(receipt.status(), "reinstatement transaction reverted");

    assert!(registry.isAccepted(victim).call().await.unwrap());
    assert_eq!(
        registry.statusOf(victim).call().await.unwrap(),
        STATUS_ACCEPTED
    );
    assert_eq!(registry.policyRevision().call().await.unwrap(), 3);
    assert_eq!(
        registry.acceptedCount().call().await.unwrap(),
        U256::from(admission_ids.len())
    );
    assert_eq!(
        registry.activePolicyHash().call().await.unwrap(),
        revision_3_hash
    );
    assert_eq!(
        registry.bootstrapPolicyHash().call().await.unwrap(),
        policy_hash
    );
}
