// use alloy::network::ReceiptResponse;
use alloy::{
    network::{EthereumWallet, TransactionBuilder}, primitives::Bytes, providers::{Provider, ProviderBuilder}, rpc::types::TransactionRequest, signers::local::PrivateKeySigner
};
use serde::{Deserialize, Serialize};
use std::fs;

pub const ANVIL_ALICE_PK: &str =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

#[derive(Debug, Deserialize, Serialize)]
struct ContractArtifact {
    abi: serde_json::Value,
    bytecode: BytecodeObject,
}

#[derive(Debug, Deserialize, Serialize)]
struct BytecodeObject {
    object: String, // This corresponds to "bytecode": { "object": "0x..." }
}

/// Deploys a smart contract to an Ethereum-compatible blockchain.
///
/// # Arguments
///
/// * `foundry_json_path` - A string slice representing the path to the Foundry JSON artifact containing the contract's bytecode.
/// * `sk` - A string slice representing the private key used to sign the deployment transaction.
/// * `rpc` - A string slice representing the RPC URL of the Ethereum node.
///
/// # Returns
///
/// * `Result<(), anyhow::Error>` - Returns `Ok(())` if the contract deployment is successful, or an `anyhow::Error` if an error occurs.
pub async fn deploy_contract(
    foundry_json_path: &str,
    sk: &str,
    rpc: &str,
) -> Result<(), anyhow::Error> {
    // Read contract bytecode from Foundry JSON
    // This can be created with `forge build` and the looking in the `out` directory.
    let file_content = fs::read_to_string(foundry_json_path)?;
    let artifact: ContractArtifact = serde_json::from_str(&file_content)?;
    let bytecode_str = artifact.bytecode.object;
    let bytecode = Bytes::from(hex::decode(bytecode_str.trim_start_matches("0x"))?);

    // Set up signer with the provided sk
    let signer: PrivateKeySigner = sk.parse().unwrap();
    let wallet = EthereumWallet::from(signer);
    let rpc_url = reqwest::Url::parse(rpc).unwrap();
    let provider = ProviderBuilder::new().wallet(wallet).on_http(rpc_url);

    // Deploy contract
    // println!("Deploying contract...");
    let gas_price = provider.get_gas_price().await?;
    let gas_limit = 5_000_000u64;
    let tx = TransactionRequest::default()
        .with_deploy_code(bytecode)
        .with_gas_price(gas_price)
        .with_gas_limit(gas_limit);
    match provider.send_transaction(tx).await {
        Ok(_pending_tx) => {
            // let receipt = _pending_tx.watch().await?;
            // println!("Transaction receipt: {:?}", receipt);
            // io::stdout().flush().unwrap();
        },
        Err(err) => println!("Error during send_transaction: {:?}", err),
    }

    Ok(())
}