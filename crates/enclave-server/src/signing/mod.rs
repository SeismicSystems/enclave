pub mod handlers;

use crate::{get_secp256k1_pk, get_secp256k1_sk};
use anyhow::{anyhow, Result};
use seismic_enclave::secp256k1_sign_digest;

/// Signs the provided data using the enclave's private key
pub fn enclave_sign(data: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
    let sk = get_secp256k1_sk();
    let signature = secp256k1_sign_digest(data, sk)
        .map_err(|e| anyhow!("Internal Error while signing the message: {:?}", e))?;
    Ok(signature)
}
