use alloy::{
    network::{EthereumWallet, TransactionBuilder},
    primitives::{Bytes, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
    sol,
};
use serde::{Deserialize, Serialize};
use std::fs;

// Generate contract bindings for the factory
sol! {
    #[sol(rpc)]
    interface UpgradeOperatorFactory {
        function deployUpgradeOperator(bytes32 salt) external returns (address);
        function computeAddress(bytes32 salt) external view returns (address);
        function isDeployed(address contractAddress) external view returns (bool);
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
    let wallet = EthereumWallet::from(signer);
    let rpc_url = reqwest::Url::parse(rpc).unwrap();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(rpc_url);

    // Create factory contract instance
    let factory_contract =
        UpgradeOperatorFactory::new(factory_address, std::sync::Arc::new(provider.clone()));

    // Compute the expected address first
    let expected_address = factory_contract
        .computeAddress(salt.into())
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
        .computeAddress(salt.into())
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
