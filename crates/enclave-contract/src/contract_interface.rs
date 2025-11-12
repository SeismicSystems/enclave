//! Contract interface definitions and types

use alloy::{
    network::EthereumWallet,
    primitives::{FixedBytes, Log},
    providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
    sol,
};

use crate::{Measurements, MultisigUpgradeOperator::ProposalCreated};

// Generate contract bindings for the upgrade operator
sol! {
    #[sol(rpc)]
    interface UpgradeOperator {
        struct Measurements {
            string tag;
            bytes mrtd;
            bytes mrseam;
            uint8[] registrar_slots;
            bytes[] registrar_values;
        }
        function acceptedMeasurments(bytes32) public returns(Measurements);
        function deprecatedMeasurments(bytes32) public returns(Measurements);
        function acceptedTags() public returns(bytes32[]);
        function deprecatedTags() public returns(bytes32[]);

        function addAcceptedMeasurements(Measurements measurements) external;
        function reinstateMeasurement(Measurements measurements) external;
        function deprecateMeasurements(Measurements measurements) external;
        function isAccepted(bytes32 measurementHash) external view returns(bool);
        function isDeprecated(bytes32 measurementHash) external view returns(bool);
        function getAcceptedMeasurement(bytes32 measurementHash) external view returns(Measurements);
        function getAcceptedCount() external view returns (uint256);
        function OWNER() external view returns (address);
        function getMeasurementHash(Measurements measurements) external pure returns(bytes32);
    }
// Generate contract bindings for the multisig contract
    #[sol(rpc)]
    interface MultisigUpgradeOperator {
        event ProposalCreated(bytes32 indexed proposalId,uint8 indexed proposalType,string tag,uint256 nonce);

        function proposeAddMeasurements(UpgradeOperator.Measurements measurements) external returns(bytes32 proposalId);
        function proposeDeprecateMeasurements(UpgradeOperator.Measurements measurements) external returns(bytes32 proposalId);
        function proposeReinstateMeasurements(UpgradeOperator.Measurements measurements) external returns(bytes32 proposalId);
        function vote(bytes32 proposalId) external;
        function executeProposal(bytes32 proposalId) external;
        function getVoteStatus(bytes32 proposalId) external view returns (uint256 voteCount, bool hasVoted1, bool hasVoted2, bool hasVoted3, bool canExecute);
        function proposalNonce() external view returns (uint256);
        function signer1() external view returns (address);
        function signer2() external view returns (address);
        function signer3() external view returns (address);
        function upgradeOperator() external view returns (address);
    }
}

/// Creates a proposal in the MultisigUpgradeOperator contract.
///
/// # Arguments
///
/// * `multisig_address` - The address of the MultisigUpgradeOperator contract.
/// * `sk` - A string slice representing the private key used to sign the transaction.
/// * `rpc` - A string slice representing the RPC URL of the Ethereum node.
/// * `params` - The proposal parameters for the proposal.
/// * `status` - The status to set.
///
/// # Returns
///
/// * `Result<([u8; 32], u64), anyhow::Error>` - Returns (proposal_id, nonce) if successful, or an `anyhow::Error` if an error occurs.
pub async fn create_multisig_proposal(
    multisig_address: alloy::primitives::Address,
    sk: &str,
    rpc: &str,
    params: Measurements,
) -> Result<FixedBytes<32>, anyhow::Error> {
    // Set up signer with the provided sk
    let signer: PrivateKeySigner = sk.parse().unwrap();
    let wallet = EthereumWallet::from(signer.clone());
    let rpc_url = reqwest::Url::parse(rpc).unwrap();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(rpc_url);

    // Create multisig contract instance
    let multisig_contract =
        MultisigUpgradeOperator::new(multisig_address, std::sync::Arc::new(provider.clone()));

    // Create proposal
    let create_tx = multisig_contract.proposeAddMeasurements(params);
    let create_pending = create_tx.send().await.map_err(|e| {
        anyhow::anyhow!(
            "create_multisig_proposal create proposal tx failed: {:?}",
            e
        )
    })?;

    // wait for it to be included
    let receipt = create_pending
        .get_receipt()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get proposal creation receipt: {:?}", e))?;

    let event: Log<ProposalCreated> = receipt.decoded_log().unwrap();

    let proposal_id = event.proposalId;

    Ok(proposal_id)
}

/// Votes on a proposal in the MultisigUpgradeOperator contract.
///
/// # Arguments
///
/// * `multisig_address` - The address of the MultisigUpgradeOperator contract.
/// * `sk` - A string slice representing the private key used to sign the transaction.
/// * `rpc` - A string slice representing the RPC URL of the Ethereum node.
/// * `proposal_id` - The proposal ID to vote on.
/// * `approved` - Whether to approve the proposal.
///
/// # Returns
///
/// * `Result<(), anyhow::Error>` - Returns success or an `anyhow::Error` if an error occurs.
pub async fn vote_on_multisig_proposal(
    multisig_address: alloy::primitives::Address,
    sk: &str,
    rpc: &str,
    proposal_id: FixedBytes<32>,
) -> Result<(), anyhow::Error> {
    // Set up signer with the provided sk
    let signer: PrivateKeySigner = sk.parse().unwrap();
    let wallet = EthereumWallet::from(signer);
    let rpc_url = reqwest::Url::parse(rpc).unwrap();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(rpc_url);

    // Create multisig contract instance
    let multisig_contract =
        MultisigUpgradeOperator::new(multisig_address, std::sync::Arc::new(provider));

    // Vote on proposal
    let vote_tx = multisig_contract.vote(proposal_id);
    let vote_pending = vote_tx
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to vote on proposal: {:?}", e))?;

    let _vote_receipt = vote_pending
        .watch()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get vote receipt: {:?}", e))?;

    println!("Voted on proposal:{:?}", proposal_id);

    Ok(())
}

/// Executes a proposal in the MultisigUpgradeOperator contract.
///
/// # Arguments
///
/// * `multisig_address` - The address of the MultisigUpgradeOperator contract.
/// * `sk` - A string slice representing the private key used to sign the transaction.
/// * `rpc` - A string slice representing the RPC URL of the Ethereum node.
/// * `params` - The proposal parameters for the proposal.
/// * `status` - The status to set.
/// * `nonce` - The nonce to use for the proposal execution.
///
/// # Returns
///
/// * `Result<(), anyhow::Error>` - Returns success or an `anyhow::Error` if an error occurs.
pub async fn execute_multisig_proposal(
    multisig_address: alloy::primitives::Address,
    sk: &str,
    rpc: &str,
    params: FixedBytes<32>,
) -> Result<(), anyhow::Error> {
    // Set up signer with the provided sk
    let signer: PrivateKeySigner = sk.parse().unwrap();
    let wallet = EthereumWallet::from(signer);
    let rpc_url = reqwest::Url::parse(rpc).unwrap();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(rpc_url);

    // Create multisig contract instance
    let multisig_contract =
        MultisigUpgradeOperator::new(multisig_address, std::sync::Arc::new(provider));

    // Execute proposal
    let execute_tx = multisig_contract.executeProposal(params);
    let execute_pending = execute_tx
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to execute proposal: {:?}", e))?;

    let _execute_receipt = execute_pending
        .watch()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get execution receipt: {:?}", e))?;

    println!("Proposal executed successfully");

    Ok(())
}

/// Checks if a proposal can be executed in the MultisigUpgradeOperator contract.
///
/// # Arguments
///
/// * `multisig_address` - The address of the MultisigUpgradeOperator contract.
/// * `rpc` - A string slice representing the RPC URL of the Ethereum node.
/// * `proposal_id` - The proposal ID to check.
///
/// # Returns
///
/// * `Result<bool, anyhow::Error>` - Returns true if the proposal can be executed, or an `anyhow::Error` if an error occurs.
pub async fn can_execute_multisig_proposal(
    multisig_address: alloy::primitives::Address,
    rpc: &str,
    proposal_id: FixedBytes<32>,
) -> Result<bool, anyhow::Error> {
    let rpc_url = reqwest::Url::parse(rpc).unwrap();
    let provider = ProviderBuilder::new().connect_http(rpc_url);

    // Create multisig contract instance
    let multisig_contract =
        MultisigUpgradeOperator::new(multisig_address, std::sync::Arc::new(provider));

    // Check if proposal can be executed
    let res = multisig_contract
        .getVoteStatus(proposal_id)
        .call()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to check if proposal can be executed: {:?}", e))?;

    Ok(res.canExecute)
}

/// Gets the vote count for a proposal in the MultisigUpgradeOperator contract.
///
/// # Arguments
///
/// * `multisig_address` - The address of the MultisigUpgradeOperator contract.
/// * `rpc` - A string slice representing the RPC URL of the Ethereum node.
/// * `proposal_id` - The proposal ID to check.
///
/// # Returns
///
/// * `Result<(u64, u64), anyhow::Error>` - Returns (approval_count, total_votes) if successful, or an `anyhow::Error` if an error occurs.
pub async fn get_multisig_vote_count(
    multisig_address: alloy::primitives::Address,
    rpc: &str,
    proposal_id: FixedBytes<32>,
) -> Result<u64, anyhow::Error> {
    let rpc_url = reqwest::Url::parse(rpc).unwrap();
    let provider = ProviderBuilder::new().connect_http(rpc_url);

    // Create multisig contract instance
    let multisig_contract =
        MultisigUpgradeOperator::new(multisig_address, std::sync::Arc::new(provider));

    // Get vote count
    let res = multisig_contract
        .getVoteStatus(proposal_id)
        .call()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get vote count: {:?}", e))?;

    Ok(res.voteCount.try_into().unwrap())
}

/// Checks if a proposal configuration is approved in the UpgradeOperator contract.
///
/// # Arguments
///
/// * `upgrade_operator_address` - The address of the UpgradeOperator contract.
/// * `rpc` - A string slice representing the RPC URL of the Ethereum node.
/// * `params` - The proposal parameters to check.
///
/// # Returns
///
/// * `Result<bool, anyhow::Error>` - Returns true if the proposal is approved, or an `anyhow::Error` if an error occurs.
pub async fn check_proposal_status(
    upgrade_operator_address: alloy::primitives::Address,
    rpc: &str,
    params: Measurements,
) -> Result<bool, anyhow::Error> {
    let rpc_url = reqwest::Url::parse(rpc).unwrap();
    let provider = ProviderBuilder::new().connect_http(rpc_url);

    // Create upgrade operator contract instance
    let upgrade_operator_contract =
        UpgradeOperator::new(upgrade_operator_address, std::sync::Arc::new(provider));

    let measurement_hash = upgrade_operator_contract
        .getMeasurementHash(params)
        .call()
        .await
        .map_err(|e| anyhow::anyhow!("get_measurement_hash failed: {:?}", e))?;

    // Check proposal status
    let status = upgrade_operator_contract
        .isAccepted(measurement_hash)
        .call()
        .await
        .map_err(|e| anyhow::anyhow!("check_proposal_status_v1 failed: {:?}", e))?;

    Ok(status)
}
