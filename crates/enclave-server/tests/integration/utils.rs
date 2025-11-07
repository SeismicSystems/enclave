use alloy::{
    network::{EthereumWallet, TransactionBuilder},
    primitives::U256,
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
};

use seismic_enclave_server::Args;

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

/// Gets the balance of an account in wei.
///
/// # Arguments
///
/// * `address` - The address of the account to check.
/// * `rpc` - A string slice representing the RPC URL of the Ethereum node.
///
/// # Returns
///
/// * `Result<u128, anyhow::Error>` - Returns the balance in wei if successful, or an `anyhow::Error` if an error occurs.
pub async fn get_balance(
    address: alloy::primitives::Address,
    rpc: &str,
) -> Result<u128, anyhow::Error> {
    let rpc_url = reqwest::Url::parse(rpc).unwrap();
    let provider = ProviderBuilder::new().connect_http(rpc_url);

    let balance = provider
        .get_balance(address)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get balance: {:?}", e))?;

    Ok(balance.try_into().unwrap())
}

pub fn get_args(n: u16, genesis_node: bool, peers: Vec<String>) -> Args {
    let port = 7878 + n;
    Args {
        ip: "0.0.0.0".to_string(),
        port,
        genesis_node,
        peers,
        reth_rpc_url: "0.0.0.0:8545".to_string(),
    }
}
