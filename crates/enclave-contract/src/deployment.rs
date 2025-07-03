use alloy::{
    network::{EthereumWallet, TransactionBuilder},
    primitives::{Bytes, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
};
use serde::{Deserialize, Serialize};
use std::fs;

// Import contract interfaces from contract_interface module
use crate::contract_interface::{UpgradeOperator, UpgradeOperatorFactory, MultisigUpgradeOperator};

/// Prints a string to standard output and immediately flushes the output buffer.
/// Useful to see prints immediately during long-running Cargo tests.
pub fn print_flush<S: AsRef<str>>(s: S) {
    use std::io::Write;
    let stdout = std::io::stdout();
    let mut handle = stdout.lock(); // lock ensures safe writing
    write!(handle, "{}", s.as_ref()).unwrap();
    handle.flush().unwrap();
}

/// Represents the proposal parameters for upgrade validation
/// This struct makes it easy to change the parameters in the future
/// To change parameters, just modify this struct and update the contract interfaces
#[derive(Debug, Clone)]
pub struct ProposalParams {
    pub mrtd: Bytes,      // 48 bytes
    pub mrseam: Bytes,    // 48 bytes
    pub pcr4: Bytes,      // 48 bytes
}

impl ProposalParams {
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



// Anvil's first secret key that they publically expose and fund for testing
pub const ANVIL_ALICE_SK: &str =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

pub const ANVIL_BOB_SK: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

pub const ANVIL_CHARLIE_SK: &str =
    "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";

#[derive(Debug, Deserialize, Serialize)]
struct ContractArtifact {
    abi: serde_json::Value,
    bytecode: BytecodeObject,
}

#[derive(Debug, Deserialize, Serialize)]
struct BytecodeObject {
    object: String, // This corresponds to "bytecode": { "object": "0x..." }
}

/// Deploys the factory contract and returns its address.
///
/// # Arguments
///
/// * `factory_json_path` - A string slice representing the path to the Foundry JSON artifact containing the factory contract's bytecode.
/// * `sk` - A string slice representing the private key used to sign the deployment transaction.
/// * `rpc` - A string slice representing the RPC URL of the Ethereum node.
///
/// # Returns
///
/// * `Result<alloy::primitives::Address, anyhow::Error>` - Returns the factory address if successful, or an `anyhow::Error` if an error occurs.
pub async fn deploy_factory(
    factory_json_path: &str,
    sk: &str,
    rpc: &str,
) -> Result<alloy::primitives::Address, anyhow::Error> {
    // Read factory contract bytecode from Foundry JSON
    let file_content = fs::read_to_string(factory_json_path)
        .map_err(|e| anyhow::anyhow!("Failed to read Foundry JSON file: {:?}", e))?;
    let artifact: ContractArtifact = serde_json::from_str(&file_content)?;
    let bytecode_str = artifact.bytecode.object;
    let bytecode = Bytes::from(hex::decode(bytecode_str.trim_start_matches("0x"))?);

    // Set up signer with the provided sk
    let signer: PrivateKeySigner = sk.parse().unwrap();
    let wallet = EthereumWallet::from(signer);
    let rpc_url = reqwest::Url::parse(rpc).unwrap();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(rpc_url);

    // Deploy factory contract
    let gas_price = provider.get_gas_price().await?;
    let gas_limit = 5_000_000u64;
    let tx = TransactionRequest::default()
        .with_deploy_code(bytecode)
        .with_gas_price(gas_price)
        .with_gas_limit(gas_limit);

    let pending_tx = provider
        .send_transaction(tx)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to deploy factory contract: {:?}", e))?;

    // Wait for the transaction to be mined
    let receipt = pending_tx
        .get_receipt()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get transaction receipt: {:?}", e))?;

    let factory_address = receipt
        .contract_address
        .ok_or_else(|| anyhow::anyhow!("No contract address in receipt"))?;

    println!("Factory deployed at: {:?}", factory_address);

    Ok(factory_address)
}

/// Deploys a contract using CREATE2 through an existing factory contract.
///
/// # Arguments
///
/// * `factory_address` - The address of the existing factory contract.
/// * `sk` - A string slice representing the private key used to sign the deployment transaction.
/// * `rpc` - A string slice representing the RPC URL of the Ethereum node.
/// * `salt` - A 32-byte salt value for CREATE2 deployment.
///
/// # Returns
///
/// * `Result<alloy::primitives::Address, anyhow::Error>` - Returns the deployed contract address if successful, or an `anyhow::Error` if an error occurs.
pub async fn deploy_via_factory_create2(
    factory_address: alloy::primitives::Address,
    sk: &str,
    rpc: &str,
    salt: [u8; 32],
) -> Result<alloy::primitives::Address, anyhow::Error> {
    // Set up signer with the provided sk
    let signer: PrivateKeySigner = sk.parse().unwrap();
    let signer_address = signer.address();
    let wallet = EthereumWallet::from(signer);
    let rpc_url = reqwest::Url::parse(rpc).unwrap();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(rpc_url);

    // Create factory contract instance
    let factory_contract =
        UpgradeOperatorFactory::new(factory_address, std::sync::Arc::new(provider.clone()));

    // Compute the expected address first (with msg.sender as owner)
    let expected_address = factory_contract
        .computeUpgradeOperatorAddressWithOwner(salt.into(), signer_address)
        .call()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to compute CREATE2 address: {:?}", e))?;

    println!("Expected CREATE2 address: {:?}", expected_address);

    // Deploy using CREATE2
    let deploy_tx = factory_contract.deployUpgradeOperator(salt.into());
    let deploy_pending = deploy_tx
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to deploy via CREATE2: {:?}", e))?;

    let _deploy_receipt = deploy_pending
        .watch()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get CREATE2 deployment receipt: {:?}", e))?;

    // Verify the contract was deployed at the expected address
    let is_deployed = factory_contract
        .isDeployed(expected_address)
        .call()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to check if contract is deployed: {:?}", e))?;

    if !is_deployed {
        return Err(anyhow::anyhow!(
            "Contract was not deployed at expected address"
        ));
    }

    println!(
        "Contract successfully deployed via CREATE2 at: {:?}",
        expected_address
    );

    Ok(expected_address)
}

/// Deploys both an UpgradeOperator and a MultisigUpgradeOperator that controls it.
///
/// # Arguments
///
/// * `factory_address` - The address of the existing factory contract.
/// * `sk` - A string slice representing the private key used to sign the deployment transaction.
/// * `rpc` - A string slice representing the RPC URL of the Ethereum node.
/// * `upgrade_operator_salt` - A 32-byte salt value for UpgradeOperator CREATE2 deployment.
/// * `multisig_salt` - A 32-byte salt value for MultisigUpgradeOperator CREATE2 deployment.
///
/// # Returns
///
/// * `Result<(alloy::primitives::Address, alloy::primitives::Address), anyhow::Error>` - Returns the deployed contract addresses if successful, or an `anyhow::Error` if an error occurs.
pub async fn deploy_upgrade_operator_with_multisig(
    factory_address: alloy::primitives::Address,
    sk: &str,
    rpc: &str,
    upgrade_operator_salt: [u8; 32],
    multisig_salt: [u8; 32],
) -> Result<(alloy::primitives::Address, alloy::primitives::Address), anyhow::Error> {
    // Set up signer with the provided sk
    let signer: PrivateKeySigner = sk.parse().unwrap();
    let wallet = EthereumWallet::from(signer);
    let rpc_url = reqwest::Url::parse(rpc).unwrap();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(rpc_url);

    // Create factory contract instance
    let factory_contract =
        UpgradeOperatorFactory::new(factory_address, std::sync::Arc::new(provider.clone()));

    // Deploy both contracts using the factory's combined function
    let deploy_tx = factory_contract
        .deployUpgradeOperatorWithMultisig(upgrade_operator_salt.into(), multisig_salt.into());
    let deploy_pending = deploy_tx
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to deploy via CREATE2: {:?}", e))?;

    let _deploy_receipt = deploy_pending
        .watch()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get CREATE2 deployment receipt: {:?}", e))?;

    // Compute the predicted addresses
    let predicted_multisig_address = factory_contract
        .computeMultisigUpgradeOperatorAddress(
            multisig_salt.into(),
            alloy::primitives::Address::ZERO,
        )
        .call()
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "Failed to compute MultisigUpgradeOperator CREATE2 address: {:?}",
                e
            )
        })?;

    let predicted_upgrade_operator_address = factory_contract
        .computeUpgradeOperatorAddressWithOwner(
            upgrade_operator_salt.into(),
            predicted_multisig_address,
        )
        .call()
        .await
        .map_err(|e| {
            anyhow::anyhow!("Failed to compute UpgradeOperator CREATE2 address: {:?}", e)
        })?;

    // Verify the contracts were deployed at the expected addresses
    let is_upgrade_operator_deployed = factory_contract
        .isDeployed(predicted_upgrade_operator_address)
        .call()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to check if UpgradeOperator is deployed: {:?}", e))?;

    let is_multisig_deployed = factory_contract
        .isDeployed(predicted_multisig_address)
        .call()
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "Failed to check if MultisigUpgradeOperator is deployed: {:?}",
                e
            )
        })?;

    if !is_upgrade_operator_deployed {
        return Err(anyhow::anyhow!(
            "UpgradeOperator was not deployed at expected address"
        ));
    }

    if !is_multisig_deployed {
        return Err(anyhow::anyhow!(
            "MultisigUpgradeOperator was not deployed at expected address"
        ));
    }

    println!(
        "UpgradeOperator successfully deployed via CREATE2 at: {:?}",
        predicted_upgrade_operator_address
    );
    println!(
        "MultisigUpgradeOperator successfully deployed via CREATE2 at: {:?}",
        predicted_multisig_address
    );

    Ok((
        predicted_upgrade_operator_address,
        predicted_multisig_address,
    ))
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
    params: &ProposalParams,
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
    params: &ProposalParams,
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
pub async fn check_proposal_status(
    upgrade_operator_address: alloy::primitives::Address,
    rpc: &str,
    params: &ProposalParams,
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
