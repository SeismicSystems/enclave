pub mod handlers;

use anyhow::{anyhow, Result};
use seismic_enclave::secp256k1_sign_digest;

use crate::key_manager::NetworkKeyProvider;

/// Signs the provided data using the enclave's private key
pub fn enclave_sign(kp: &dyn NetworkKeyProvider, data: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
    let sk = kp.get_tx_io_sk();
    let signature = secp256k1_sign_digest(data, sk)
        .map_err(|e| anyhow!("Internal Error while signing the message: {:?}", e))?;
    Ok(signature)
}
