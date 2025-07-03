//! Contract interface definitions and types

use alloy::{
    sol,
    primitives::{Bytes, U256},
    network::{EthereumWallet, TransactionBuilder},
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
};


// Generate contract bindings for the factory
sol! {
    #[sol(rpc)]
    interface UpgradeOperatorFactory {
        function deployUpgradeOperator(bytes32 salt) external returns (address);
        function deployUpgradeOperatorWithOwner(bytes32 salt, address owner) external returns (address);
        function deployMultisigUpgradeOperator(bytes32 salt, address upgradeOperator) external returns (address);
        function deployUpgradeOperatorWithMultisig(bytes32 upgradeOperatorSalt, bytes32 multisigSalt) external returns (address, address);
        function computeUpgradeOperatorAddress(bytes32 salt) external view returns (address);
        function computeUpgradeOperatorAddressWithOwner(bytes32 salt, address owner) external view returns (address);
        function computeMultisigUpgradeOperatorAddress(bytes32 salt, address upgradeOperator) external view returns (address);
        function isDeployed(address contractAddress) external view returns (bool);
    }
}

// Generate contract bindings for the upgrade operator
sol! {
    #[sol(rpc)]
    interface UpgradeOperator {
        function set_id_status_v1(bytes mrtd, bytes mrseam, bytes pcr4, bool status) external;
        function get_id_status_v1(bytes mrtd, bytes mrseam, bytes pcr4) external view returns (bool);
        function computeIdV1(bytes mrtd, bytes mrseam, bytes pcr4) external pure returns (bytes32);
        function owner() external view returns (address);
    }
}

// Generate contract bindings for the multisig contract
sol! {
    #[sol(rpc)]
    interface MultisigUpgradeOperator {
        function createProposalV1(bytes mrtd, bytes mrseam, bytes pcr4, bool status) external returns (bytes32);
        function vote(bytes32 proposalId, bool approved) external;
        function executeProposalV1(bytes mrtd, bytes mrseam, bytes pcr4, bool status, uint256 nonce) external;
        function getVoteCount(bytes32 proposalId) external view returns (uint256 approvalCount, uint256 totalVotes);
        function canExecute(bytes32 proposalId) external view returns (bool);
        function computeProposalIdV1(bytes mrtd, bytes mrseam, bytes pcr4, bool status, uint256 nonce) external view returns (bytes32);
        function proposalNonce() external view returns (uint256);
        function signer1() external view returns (address);
        function signer2() external view returns (address);
        function signer3() external view returns (address);
        function upgradeOperator() external view returns (address);
        function setUpgradeOperator(address _upgradeOperator) external;
        function factory() external view returns (address);
    }
}


/// Represents the proposal parameters for upgrade validation
/// This struct makes it easy to change the parameters in the future
/// To change parameters, just modify this struct and update the contract interfaces
#[derive(Debug, Clone)]
pub struct ProposalParamsV1 {
    pub mrtd: Bytes,      // 48 bytes
    pub mrseam: Bytes,    // 48 bytes
    pub pcr4: Bytes,      // 48 bytes
}

impl ProposalParamsV1 {
    /// Creates a new ProposalParams instance
    pub fn new(mrtd: Bytes, mrseam: Bytes, pcr4: Bytes) -> Self {
        Self { mrtd, mrseam, pcr4 }
    }
    
    /// Creates test proposal parameters with default values
    pub fn test_params() -> Self {
        Self {
            mrtd: Bytes::from(vec![0xbb; 48]),
            mrseam: Bytes::from(vec![0xcc; 48]),
            pcr4: Bytes::from(vec![0xdd; 48]),
        }
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
    params: &ProposalParamsV1,
    status: bool,
) -> Result<([u8; 32], u64), anyhow::Error> {
    // Set up signer with the provided sk
    let signer: PrivateKeySigner = sk.parse().unwrap();
    let wallet = EthereumWallet::from(signer);
    let rpc_url = reqwest::Url::parse(rpc).unwrap();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(rpc_url);

    // Create multisig contract instance
    let multisig_contract =
        MultisigUpgradeOperator::new(multisig_address, std::sync::Arc::new(provider.clone()));

    // Get current nonce before creating proposal (for debugging/logging if needed)
    let _current_nonce = multisig_contract
        .proposalNonce()
        .call()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get current nonce: {:?}", e))?;

    // Create proposal
    let create_tx = multisig_contract.createProposalV1(
        params.mrtd.clone(),
        params.mrseam.clone(),
        params.pcr4.clone(),
        status,
    );
    let create_pending = create_tx
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create proposal: {:?}", e))?;

    let _create_receipt = create_pending
        .watch()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get proposal creation receipt: {:?}", e))?;

    // Get the new nonce after proposal creation
    let new_nonce = multisig_contract
        .proposalNonce()
        .call()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get new nonce: {:?}", e))?;

    // Compute the proposal ID using the new nonce
    let proposal_id = multisig_contract
        .computeProposalIdV1(params.mrtd.clone(), params.mrseam.clone(), params.pcr4.clone(), status, new_nonce)
        .call()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to compute proposal ID: {:?}", e))?;

    println!(
        "Proposal created with ID: {:?}, nonce: {}",
        proposal_id, new_nonce
    );

    Ok((proposal_id.into(), new_nonce.try_into().unwrap()))
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
    proposal_id: [u8; 32],
    approved: bool,
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
    let vote_tx = multisig_contract.vote(proposal_id.into(), approved);
    let vote_pending = vote_tx
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to vote on proposal: {:?}", e))?;

    let _vote_receipt = vote_pending
        .watch()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get vote receipt: {:?}", e))?;

    println!("Voted {} on proposal: {:?}", approved, proposal_id);

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
    params: &ProposalParamsV1,
    status: bool,
    nonce: u64,
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
    let execute_tx = multisig_contract.executeProposalV1(
        params.mrtd.clone(),
        params.mrseam.clone(),
        params.pcr4.clone(),
        status,
        U256::from(nonce),
    );
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
    proposal_id: [u8; 32],
) -> Result<bool, anyhow::Error> {
    let rpc_url = reqwest::Url::parse(rpc).unwrap();
    let provider = ProviderBuilder::new().connect_http(rpc_url);

    // Create multisig contract instance
    let multisig_contract =
        MultisigUpgradeOperator::new(multisig_address, std::sync::Arc::new(provider));

    // Check if proposal can be executed
    let can_execute = multisig_contract
        .canExecute(proposal_id.into())
        .call()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to check if proposal can be executed: {:?}", e))?;

    Ok(can_execute)
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
    proposal_id: [u8; 32],
) -> Result<(u64, u64), anyhow::Error> {
    let rpc_url = reqwest::Url::parse(rpc).unwrap();
    let provider = ProviderBuilder::new().connect_http(rpc_url);

    // Create multisig contract instance
    let multisig_contract =
        MultisigUpgradeOperator::new(multisig_address, std::sync::Arc::new(provider));

    // Get vote count
    let result = multisig_contract
        .getVoteCount(proposal_id.into())
        .call()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get vote count: {:?}", e))?;

    Ok((
        result.approvalCount.try_into().unwrap(),
        result.totalVotes.try_into().unwrap(),
    ))
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
pub async fn check_proposal_status_v1(
    upgrade_operator_address: alloy::primitives::Address,
    rpc: &str,
    params: &ProposalParamsV1,
) -> Result<bool, anyhow::Error> {
    let rpc_url = reqwest::Url::parse(rpc).unwrap();
    let provider = ProviderBuilder::new().connect_http(rpc_url);

    // Create upgrade operator contract instance
    let upgrade_operator_contract =
        UpgradeOperator::new(upgrade_operator_address, std::sync::Arc::new(provider));

    // Check proposal status
    let status = upgrade_operator_contract
        .get_id_status_v1(params.mrtd.clone(), params.mrseam.clone(), params.pcr4.clone())
        .call()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to check proposal status: {:?}", e))?;

    Ok(status)
}

/// Computes the CREATE2 address for a contract without deploying it.
///
/// # Arguments
///
/// * `factory_address` - The address of the factory contract.
/// * `rpc` - A string slice representing the RPC URL of the Ethereum node.
/// * `salt` - A 32-byte salt value for CREATE2 deployment.
///
/// # Returns
///
/// * `Result<alloy::primitives::Address, anyhow::Error>` - Returns the computed CREATE2 address if successful, or an `anyhow::Error` if an error occurs.
pub async fn compute_create2_address(
    factory_address: alloy::primitives::Address,
    rpc: &str,
    salt: [u8; 32],
) -> Result<alloy::primitives::Address, anyhow::Error> {
    let rpc_url = reqwest::Url::parse(rpc).unwrap();
    let provider = ProviderBuilder::new().connect_http(rpc_url);

    let factory_contract =
        UpgradeOperatorFactory::new(factory_address, std::sync::Arc::new(provider));

    let expected_address = factory_contract
        .computeUpgradeOperatorAddress(salt.into())
        .call()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to compute CREATE2 address: {:?}", e))?;

    Ok(expected_address)
}

/// Sends ETH from one account to another to trigger transaction persistence.
///
/// # Arguments
///
/// * `from_sk` - The private key of the sender account.
/// * `to_address` - The address of the recipient.
/// * `amount_wei` - The amount to send in wei.
/// * `rpc` - A string slice representing the RPC URL of the Ethereum node.
///
/// # Returns
///
/// * `Result<(), anyhow::Error>` - Returns success or an `anyhow::Error` if an error occurs.
pub async fn send_eth(
    from_sk: &str,
    to_address: alloy::primitives::Address,
    amount_wei: u128,
    rpc: &str,
) -> Result<(), anyhow::Error> {
    // Set up signer with the provided sk
    let signer: PrivateKeySigner = from_sk.parse().unwrap();
    let wallet = EthereumWallet::from(signer.clone());
    let rpc_url = reqwest::Url::parse(rpc).unwrap();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(rpc_url);

    // Get the sender's address
    let from_address = signer.address();

    // Get current gas price and nonce
    let gas_price = provider.get_gas_price().await?;
    let nonce = provider.get_transaction_count(from_address).await?;

    // Create transaction request
    let tx = TransactionRequest::default()
        .with_to(to_address)
        .with_value(U256::from(amount_wei))
        .with_gas_price(gas_price)
        .with_nonce(nonce)
        .with_gas_limit(21_000u64); // Standard ETH transfer gas limit

    // Send transaction
    let pending_tx = provider
        .send_transaction(tx)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to send ETH: {:?}", e))?;

    // Wait for the transaction to be mined
    let _receipt = pending_tx
        .get_receipt()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get transaction receipt: {:?}", e))?;

    println!(
        "ETH transfer completed: {} wei from {:?} to {:?}",
        amount_wei, from_address, to_address
    );

    Ok(())
}
