use alloy::{
    network::{EthereumWallet, TransactionBuilder},
    primitives::Bytes,
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
};
use serde::{Deserialize, Serialize};
use std::fs;

// Import contract interfaces from contract_interface module
use crate::contract_interface::UpgradeOperatorFactory;

/// Prints a string to standard output and immediately flushes the output buffer.
/// Useful to see prints immediately during long-running Cargo tests.
pub fn print_flush<S: AsRef<str>>(s: S) {
    use std::io::Write;
    let stdout = std::io::stdout();
    let mut handle = stdout.lock(); // lock ensures safe writing
    write!(handle, "{}", s.as_ref()).unwrap();
    handle.flush().unwrap();
}

/// Anvil's first secret key that they publically expose and fund for testing
pub const ANVIL_ALICE_SK: &str =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

pub const ANVIL_BOB_SK: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

pub const ANVIL_CHARLIE_SK: &str =
    "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";

/// The address of the UpgradeOperator contract
/// This is the address that the factory will deploy the UpgradeOperator to
/// See the create2_test.rs test to see how this is computed
/// TODO: Figure out how Seismic intends to make this constant consistent long-term
pub const UPGRADE_OPERATOR_ADDRESS: &str = "0xb380dadc0214fb7092eb1ef4689b98716392ade1";

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