use enclave_contract::upgrades_canonical_deploy;
use enclave_contract::UPGRADE_MULTISIG_ADDRESS;
use enclave_contract::UPGRADE_OPERATOR_ADDRESS;
use enclave_contract::{
    can_execute_multisig_proposal, check_proposal_status_v1, create_multisig_proposal,
    execute_multisig_proposal, get_multisig_vote_count, print_flush, vote_on_multisig_proposal,
    ProposalParamsV1, ANVIL_ALICE_SK, ANVIL_BOB_SK,
};
use std::thread::sleep;
use std::time::Duration;

/// Test the complete multisig workflow for controlling UpgradeOperator
/// This test verifies that the multisig contract can properly control the UpgradeOperator
/// through a 2-of-3 voting mechanism
#[tokio::test(flavor = "multi_thread")]
pub async fn test_multisig_upgrade_operator_workflow() -> Result<(), anyhow::Error> {
    // Set path to the factory contract's json file
    let factory_json_path = "contracts/out/UpgradeOperatorFactory.sol/UpgradeOperatorFactory.json";
    let reth_rpc = "http://localhost:8545";
    let multisig_address = UPGRADE_MULTISIG_ADDRESS
        .parse::<alloy::primitives::Address>()
        .unwrap();
    let upgrade_operator_address = UPGRADE_OPERATOR_ADDRESS
        .parse::<alloy::primitives::Address>()
        .unwrap();

    upgrades_canonical_deploy(factory_json_path, reth_rpc)
        .await
        .unwrap();

    // Wait a bit for the transaction to be processed
    sleep(Duration::from_secs(2));

    // Test data for proposal
    let params = ProposalParamsV1::test_params();
    let status = true;

    print_flush("Creating multisig proposal...\n");

    // Create a proposal to set MRTD
    let (proposal_id, nonce) =
        create_multisig_proposal(multisig_address, ANVIL_ALICE_SK, reth_rpc, &params, status)
            .await
            .map_err(|e| anyhow::anyhow!("multisig workflow failed to create proposal: {:?}", e))?;

    print_flush(format!(
        "Proposal created with ID: {:?}, nonce: {}\n",
        proposal_id, nonce
    ));

    // Wait a bit for the transaction to be processed
    sleep(Duration::from_secs(2));

    // Check initial vote count
    let (approval_count, total_votes) =
        get_multisig_vote_count(multisig_address, reth_rpc, proposal_id)
            .await
            .map_err(|e| anyhow::anyhow!("failed to get vote count: {:?}", e))?;

    print_flush(format!(
        "Initial vote count - Approvals: {}, Total votes: {}\n",
        approval_count, total_votes
    ));
    assert_eq!(approval_count, 0, "Initial approval count should be 0");
    assert_eq!(total_votes, 0, "Initial total votes should be 0");

    // Check if proposal can be executed (should be false initially)
    let can_execute = can_execute_multisig_proposal(multisig_address, reth_rpc, proposal_id)
        .await
        .map_err(|e| anyhow::anyhow!("failed to check if proposal can be executed: {:?}", e))?;

    print_flush(format!("Can execute proposal: {}\n", can_execute));
    assert!(!can_execute, "Proposal should not be executable initially");

    print_flush("Alice voting yes on proposal...\n");

    // Alice votes yes
    vote_on_multisig_proposal(
        multisig_address,
        ANVIL_ALICE_SK,
        reth_rpc,
        proposal_id,
        true,
    )
    .await
    .map_err(|e| anyhow::anyhow!("failed to vote with Alice: {:?}", e))?;

    // Wait a bit for the transaction to be processed
    sleep(Duration::from_secs(2));

    // Check vote count after Alice's vote
    let (approval_count, total_votes) =
        get_multisig_vote_count(multisig_address, reth_rpc, proposal_id)
            .await
            .map_err(|e| anyhow::anyhow!("failed to get vote count: {:?}", e))?;

    print_flush(format!(
        "Vote count after Alice - Approvals: {}, Total votes: {}\n",
        approval_count, total_votes
    ));
    assert_eq!(
        approval_count, 1,
        "Approval count should be 1 after Alice's vote"
    );
    assert_eq!(total_votes, 1, "Total votes should be 1 after Alice's vote");

    // Check if proposal can be executed (should still be false with only 1 vote)
    let can_execute = can_execute_multisig_proposal(multisig_address, reth_rpc, proposal_id)
        .await
        .map_err(|e| anyhow::anyhow!("failed to check if proposal can be executed: {:?}", e))?;

    print_flush(format!(
        "Can execute proposal after Alice: {}\n",
        can_execute
    ));
    assert!(
        !can_execute,
        "Proposal should not be executable with only 1 vote"
    );

    print_flush("Bob voting yes on proposal...\n");

    // Bob votes yes
    vote_on_multisig_proposal(multisig_address, ANVIL_BOB_SK, reth_rpc, proposal_id, true)
        .await
        .map_err(|e| anyhow::anyhow!("failed to vote with Bob: {:?}", e))?;

    // Wait a bit for the transaction to be processed
    sleep(Duration::from_secs(2));

    // Check vote count after Bob's vote
    let (approval_count, total_votes) =
        get_multisig_vote_count(multisig_address, reth_rpc, proposal_id)
            .await
            .map_err(|e| anyhow::anyhow!("failed to get vote count: {:?}", e))?;

    print_flush(format!(
        "Vote count after Bob - Approvals: {}, Total votes: {}\n",
        approval_count, total_votes
    ));
    assert_eq!(
        approval_count, 2,
        "Approval count should be 2 after Bob's vote"
    );
    assert_eq!(total_votes, 2, "Total votes should be 2 after Bob's vote");

    // Check if proposal can be executed (should be true with 2 votes)
    let can_execute = can_execute_multisig_proposal(multisig_address, reth_rpc, proposal_id)
        .await
        .map_err(|e| anyhow::anyhow!("failed to check if proposal can be executed: {:?}", e))?;

    print_flush(format!("Can execute proposal after Bob: {}\n", can_execute));
    assert!(can_execute, "Proposal should be executable with 2 votes");

    // Check initial proposal status (should be false)
    let initial_proposal_status =
        check_proposal_status_v1(upgrade_operator_address, reth_rpc, &params)
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
    execute_multisig_proposal(
        multisig_address,
        ANVIL_ALICE_SK,
        reth_rpc,
        &params,
        status,
        nonce,
    )
    .await
    .map_err(|e| anyhow::anyhow!("failed to execute proposal: {:?}", e))?;

    // Wait a bit for the transaction to be processed
    sleep(Duration::from_secs(2));

    print_flush("Checking final proposal status...\n");

    // Check final proposal status (should be true)
    let final_proposal_status =
        check_proposal_status_v1(upgrade_operator_address, reth_rpc, &params)
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
