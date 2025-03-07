// use alloy::network::ReceiptResponse;
use alloy::{
    network::{EthereumWallet, TransactionBuilder}, primitives::Bytes, providers::{Provider, ProviderBuilder}, rpc::types::TransactionRequest, signers::local::PrivateKeySigner
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Write};

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

pub async fn deploy_contract(
    foundry_json_path: &str,
    sk: &str,
    rpc: &str,
) -> Result<(), anyhow::Error> {
    // Read contract bytecode from Foundry JSON
    let file_content = fs::read_to_string(foundry_json_path)?;
    let artifact: ContractArtifact = serde_json::from_str(&file_content)?;
    let bytecode_str = artifact.bytecode.object;
    let bytecode = Bytes::from(hex::decode(bytecode_str.trim_start_matches("0x"))?);

    // Set up signer from the first default Anvil account (Alice).
    let signer: PrivateKeySigner = sk.parse().unwrap();
    let wallet = EthereumWallet::from(signer);
    let rpc_url = reqwest::Url::parse(rpc).unwrap();
    let provider = ProviderBuilder::new().wallet(wallet).on_http(rpc_url);

    // Deploy contract
    println!("Deploying contract...");
    let gas_price = provider.get_gas_price().await?;
    let gas_limit = 5_000_000u64;
    let tx = TransactionRequest::default()
        .with_deploy_code(bytecode)
        .with_gas_price(gas_price)
        .with_gas_limit(gas_limit);
    match provider.send_transaction(tx).await {
        Ok(pending_tx) => {
            let receipt = pending_tx.watch().await?;
            println!("Transaction receipt: {:?}", receipt);
            io::stdout().flush().unwrap();
        },
        Err(err) => println!("Error during send_transaction: {:?}", err),
    }

    Ok(())
}