use enclave_contract::can_execute_multisig_proposal;
use enclave_contract::check_proposal_status;
use enclave_contract::create_multisig_proposal;
use enclave_contract::execute_multisig_proposal;
use enclave_contract::get_multisig_vote_count;
use enclave_contract::vote_on_multisig_proposal;
use enclave_contract::Measurements;
use enclave_contract::UPGRADE_MULTISIG_ADDRESS;
use enclave_contract::UPGRADE_OPERATOR_ADDRESS;

use enclave_contract::{ANVIL_ALICE_SK, ANVIL_BOB_SK};

use alloy::node_bindings::Anvil;
use alloy::primitives::{Address, Bytes};
use alloy::providers::{ext::AnvilApi, ProviderBuilder};
use std::path::PathBuf;
use std::process::Command;
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

/// Compile the upgrade contracts with `forge` and return the deployed (runtime)
/// bytecode for `name` from its foundry artifact.
///
/// seismic-reth places this same bytecode at a fixed genesis address; here we
/// build it from the checked-in sources so the test can seed it into a local
/// `anvil` node (see [`deploy_upgrade_contracts`]). The contracts are plain
/// Solidity (no shielded types), so vanilla `forge`/`anvil` — installed in CI via
/// foundryup — are all this test needs; no Seismic toolchain or node.
fn deployed_bytecode(name: &str) -> Bytes {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    // Idempotent: recompiles only when sources change. `--skip tests/**` keeps
    // the forge-std-dependent `.t.sol` out of the build (it isn't needed here).
    let status = Command::new("forge")
        .current_dir(&crate_dir)
        .args([
            "build",
            "--contracts",
            "contracts/",
            "--skip",
            "tests/**",
            "--out",
            "out",
        ])
        .status()
        .expect("failed to run `forge build` (is forge on PATH? install via foundryup)");
    assert!(status.success(), "`forge build` failed");

    let artifact = crate_dir.join(format!("out/{name}.sol/{name}.json"));
    let json: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&artifact)
            .unwrap_or_else(|e| panic!("reading artifact {}: {e}", artifact.display())),
    )
    .expect("parsing foundry artifact json");

    let hex = json["deployedBytecode"]["object"]
        .as_str()
        .expect("artifact missing deployedBytecode.object");
    hex.parse::<Bytes>()
        .expect("deployedBytecode is not valid hex")
}

/// Seed the UpgradeOperator and MultisigUpgradeOperator runtime bytecode at their
/// fixed addresses, replicating seismic-reth's genesis alloc on a local `anvil`
/// node.
///
/// Both addresses are baked into the contracts as `constant`s (the multisig's
/// `upgradeOperator`, the operator's `OWNER`), so they must land at exactly these
/// addresses for the cross-contract calls and the `onlyNetworkMultisig` guard to
/// work. Neither contract has constructor-initialized storage, so placing the
/// runtime code is sufficient — no deploy transaction or storage seeding needed.
async fn deploy_upgrade_contracts(rpc: &str) {
    let provider = ProviderBuilder::new().connect_http(rpc.parse().unwrap());

    let operator: Address = UPGRADE_OPERATOR_ADDRESS.parse().unwrap();
    let multisig: Address = UPGRADE_MULTISIG_ADDRESS.parse().unwrap();

    provider
        .anvil_set_code(operator, deployed_bytecode("UpgradeOperator"))
        .await
        .expect("anvil_setCode UpgradeOperator");
    provider
        .anvil_set_code(multisig, deployed_bytecode("MultisigUpgradeOperator"))
        .await
        .expect("anvil_setCode MultisigUpgradeOperator");
}

/// Test the complete multisig workflow for controlling UpgradeOperator
/// This test verifies that the multisig contract can properly control the UpgradeOperator
/// through a 2-of-3 voting mechanism
#[tokio::test(flavor = "multi_thread")]
pub async fn test_multisig_upgrade_operator_workflow() -> Result<(), anyhow::Error> {
    // Two modes, one binary:
    //   - Default (hosted `check_and_test`): spin up a throwaway anvil and seed
    //     the two upgrade contracts at their fixed addresses. Self-contained logic
    //     coverage — no reth, enclave-server, or TPM.
    //   - `MULTISIG_RPC=<url>` set (self-hosted `run_integration_tests.sh`): run
    //     against that node instead. There the contracts already exist at genesis
    //     (seismic-reth's dev alloc), so we skip the spawn + `anvil_setCode`. This
    //     run is the on-chain allowlist *setup* that `test_boot_share_root_key`
    //     later reads from reth at :8545.
    let _anvil; // keep the spawned node alive for the whole test in default mode
    let endpoint;
    let reth_rpc = if let Ok(rpc) = std::env::var("MULTISIG_RPC") {
        endpoint = rpc;
        endpoint.as_str()
    } else {
        let anvil = Anvil::new().try_spawn()?;
        endpoint = anvil.endpoint();
        _anvil = anvil;
        let rpc = endpoint.as_str();
        deploy_upgrade_contracts(rpc).await;
        rpc
    };

    let multisig_address = UPGRADE_MULTISIG_ADDRESS
        .parse::<alloy::primitives::Address>()
        .unwrap();
    let upgrade_operator_address = UPGRADE_OPERATOR_ADDRESS
        .parse::<alloy::primitives::Address>()
        .unwrap();

    // Wait a bit for the transaction to be processed
    sleep(Duration::from_secs(2));

    let params = Measurements {
        tag: "AzureV1".to_string(),
        mrtd: [
            254, 39, 178, 170, 58, 5, 236, 86, 134, 76, 48, 138, 255, 3, 221, 19, 193, 137, 166,
            17, 45, 33, 228, 23, 236, 26, 254, 98, 106, 140, 185, 217, 20, 130, 209, 55, 158, 192,
            47, 230, 48, 137, 114, 149, 10, 147, 13, 10,
        ]
        .into(),
        mrseam: [
            151, 144, 216, 154, 16, 33, 14, 198, 150, 138, 119, 60, 238, 44, 160, 91, 90, 169, 115,
            9, 243, 103, 39, 169, 104, 82, 123, 228, 96, 111, 193, 158, 111, 115, 172, 206, 53, 9,
            70, 201, 212, 106, 155, 247, 166, 63, 132, 48,
        ]
        .into(),
        registrar_slots: vec![0, 1, 2, 3],
        registrar_values: vec![
            [0; 48].into(),
            [0; 48].into(),
            [0; 48].into(),
            [0; 48].into(),
        ],
    };

    print_flush("Creating multisig proposal...\n");

    // Create a proposal to set MRTD
    let proposal_id =
        create_multisig_proposal(multisig_address, ANVIL_ALICE_SK, reth_rpc, params.clone())
            .await
            .map_err(|e| anyhow::anyhow!("multisig workflow failed to create proposal: {:?}", e))?;

    print_flush(format!("Proposal created with ID: {:?}\n", proposal_id));

    // Wait a bit for the transaction to be processed
    sleep(Duration::from_secs(2));

    // Check initial vote count
    let total_votes = get_multisig_vote_count(multisig_address, reth_rpc, proposal_id)
        .await
        .map_err(|e| anyhow::anyhow!("failed to get vote count: {:?}", e))?;

    print_flush(format!(
        "Initial vote count - Total votes: {}\n",
        total_votes
    ));
    assert_eq!(total_votes, 1, "Initial total votes should be 1");

    // Check if proposal can be executed (should be false initially)
    let can_execute = can_execute_multisig_proposal(multisig_address, reth_rpc, proposal_id)
        .await
        .map_err(|e| anyhow::anyhow!("failed to check if proposal can be executed: {:?}", e))?;

    print_flush(format!("Can execute proposal: {}\n", can_execute));
    assert!(!can_execute, "Proposal should not be executable initially");

    print_flush("Bob voting yes on proposal...\n");

    // Bob votes yes
    vote_on_multisig_proposal(multisig_address, ANVIL_BOB_SK, reth_rpc, proposal_id)
        .await
        .map_err(|e| anyhow::anyhow!("failed to vote with Bob: {:?}", e))?;

    // Wait a bit for the transaction to be processed
    sleep(Duration::from_secs(2));

    // Check vote count after Bob's vote
    let total_votes = get_multisig_vote_count(multisig_address, reth_rpc, proposal_id)
        .await
        .map_err(|e| anyhow::anyhow!("failed to get vote count: {:?}", e))?;

    print_flush(format!(
        "Vote count after Bob - Total votes: {}\n",
        total_votes
    ));

    assert_eq!(total_votes, 2, "Total votes should be 2 after Bob's vote");

    // Check if proposal can be executed (should be true with 2 votes)
    let can_execute = can_execute_multisig_proposal(multisig_address, reth_rpc, proposal_id)
        .await
        .map_err(|e| anyhow::anyhow!("failed to check if proposal can be executed: {:?}", e))?;

    print_flush(format!("Can execute proposal after Bob: {}\n", can_execute));
    assert!(can_execute, "Proposal should be executable with 2 votes");

    // Check initial proposal status (should be false)
    let initial_proposal_status =
        check_proposal_status(upgrade_operator_address, reth_rpc, params.clone())
            .await
            .map_err(|e| anyhow::anyhow!("failed to check initial proposal status: {:?}", e))?;

    print_flush(format!(
        "Initial proposal status: {}\n",
        initial_proposal_status
    ));
    assert!(
        !initial_proposal_status,
        "Initial proposal status should be false"
    );

    print_flush("Executing proposal...\n");

    // Execute the proposal
    execute_multisig_proposal(multisig_address, ANVIL_ALICE_SK, reth_rpc, proposal_id)
        .await
        .map_err(|e| anyhow::anyhow!("failed to execute proposal: {:?}", e))?;

    // Wait a bit for the transaction to be processed
    sleep(Duration::from_secs(2));

    print_flush("Checking final proposal status...\n");

    // Check final proposal status (should be true)
    let final_proposal_status = check_proposal_status(upgrade_operator_address, reth_rpc, params)
        .await
        .map_err(|e| anyhow::anyhow!("failed to check final proposal status: {:?}", e))?;

    print_flush(format!(
        "Final proposal status: {}\n",
        final_proposal_status
    ));
    assert!(
        final_proposal_status,
        "Final proposal status should be true"
    );

    // Test that the proposal cannot be executed again
    let can_execute_again = can_execute_multisig_proposal(multisig_address, reth_rpc, proposal_id)
        .await
        .map_err(|e| {
            anyhow::anyhow!("failed to check if proposal can be executed again: {:?}", e)
        })?;

    print_flush(format!(
        "Can execute proposal again: {}\n",
        can_execute_again
    ));
    assert!(
        !can_execute_again,
        "Proposal should not be executable again after execution"
    );

    print_flush("Test completed successfully!\n");

    Ok(())
}
