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

/// Test the complete multisig workflow for controlling UpgradeOperator
/// This test verifies that the multisig contract can properly control the UpgradeOperator
/// through a 2-of-3 voting mechanism
#[tokio::test(flavor = "multi_thread")]
pub async fn test_multisig_upgrade_operator_workflow() -> Result<(), anyhow::Error> {
    // Set path to the factory contract's json file
    let reth_rpc = "http://localhost:8545";
    let multisig_address = UPGRADE_MULTISIG_ADDRESS
        .parse::<alloy::primitives::Address>()
        .unwrap();
    let upgrade_operator_address = UPGRADE_OPERATOR_ADDRESS
        .parse::<alloy::primitives::Address>()
        .unwrap();

    // Wait a bit for the transaction to be processed
    sleep(Duration::from_secs(2));

    // Test data for proposal
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
