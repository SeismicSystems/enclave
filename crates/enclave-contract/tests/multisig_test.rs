use alloy::primitives::Bytes;
use enclave_contract::{
    can_execute_multisig_proposal, check_mrtd_status, create_multisig_proposal, deploy_factory,
    deploy_upgrade_operator_with_multisig, execute_multisig_proposal, get_multisig_vote_count,
    print_flush, vote_on_multisig_proposal, ANVIL_ALICE_SK, ANVIL_BOB_SK,
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

    // Use fixed salts for predictable testing
    let upgrade_operator_salt: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];

    let multisig_salt: [u8; 32] = [
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e,
        0x3f, 0x40,
    ];

    print_flush("Deploying factory contract...\n");

    // Deploy the factory contract first
    let factory_address = deploy_factory(factory_json_path, ANVIL_ALICE_SK, reth_rpc)
        .await
        .map_err(|e| anyhow::anyhow!("failed to deploy factory: {:?}", e))?;

    print_flush(format!("Factory deployed at: {:?}\n", factory_address));

    // Wait a bit for the transaction to be processed
    sleep(Duration::from_secs(2));

    print_flush("Deploying UpgradeOperator and MultisigUpgradeOperator via CREATE2...\n");

    // Deploy both contracts using CREATE2 through the factory
    let (upgrade_operator_address, multisig_address) = deploy_upgrade_operator_with_multisig(
        factory_address,
        ANVIL_ALICE_SK,
        reth_rpc,
        upgrade_operator_salt,
        multisig_salt,
    )
    .await
    .map_err(|e| anyhow::anyhow!("failed to deploy contracts via CREATE2: {:?}", e))?;

    print_flush(format!(
        "UpgradeOperator deployed at: {:?}\n",
        upgrade_operator_address
    ));
    print_flush(format!(
        "MultisigUpgradeOperator deployed at: {:?}\n",
        multisig_address
    ));

    // Wait a bit for the transaction to be processed
    sleep(Duration::from_secs(2));

    // Test data for MRTD
    let rootfs_hash = Bytes::from(vec![0xaa; 32]);
    let mrtd = Bytes::from(vec![0xbb; 48]);
    let rtmr0 = Bytes::from(vec![0xcc; 48]);
    let rtmr3 = Bytes::from(vec![0xdd; 48]);
    let status = true;

    print_flush("Creating multisig proposal...\n");

    // Create a proposal to set MRTD
    let (proposal_id, nonce) = create_multisig_proposal(
        multisig_address,
        ANVIL_ALICE_SK,
        reth_rpc,
        rootfs_hash.clone(),
        mrtd.clone(),
        rtmr0.clone(),
        rtmr3.clone(),
        status,
    )
    .await
    .map_err(|e| anyhow::anyhow!("failed to create proposal: {:?}", e))?;

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

    // Check initial MRTD status (should be false)
    let initial_mrtd_status = check_mrtd_status(
        upgrade_operator_address,
        reth_rpc,
        rootfs_hash.clone(),
        mrtd.clone(),
        rtmr0.clone(),
        rtmr3.clone(),
    )
    .await
    .map_err(|e| anyhow::anyhow!("failed to check initial MRTD status: {:?}", e))?;

    print_flush(format!("Initial MRTD status: {}\n", initial_mrtd_status));
    assert!(!initial_mrtd_status, "Initial MRTD status should be false");

    print_flush("Executing proposal...\n");

    // Execute the proposal
    execute_multisig_proposal(
        multisig_address,
        ANVIL_ALICE_SK,
        reth_rpc,
        rootfs_hash.clone(),
        mrtd.clone(),
        rtmr0.clone(),
        rtmr3.clone(),
        status,
        nonce,
    )
    .await
    .map_err(|e| anyhow::anyhow!("failed to execute proposal: {:?}", e))?;

    // Wait a bit for the transaction to be processed
    sleep(Duration::from_secs(2));

    print_flush("Checking final MRTD status...\n");

    // Check final MRTD status (should be true)
    let final_mrtd_status = check_mrtd_status(
        upgrade_operator_address,
        reth_rpc,
        rootfs_hash.clone(),
        mrtd.clone(),
        rtmr0.clone(),
        rtmr3.clone(),
    )
    .await
    .map_err(|e| anyhow::anyhow!("failed to check final MRTD status: {:?}", e))?;

    print_flush(format!("Final MRTD status: {}\n", final_mrtd_status));
    assert!(final_mrtd_status, "Final MRTD status should be true");

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
