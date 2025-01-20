pub mod handlers;

use crate::get_secp256k1_sk;
use anyhow::{anyhow, Result};
use secp256k1::ecdh::SharedSecret;
use secp256k1::{PublicKey, SecretKey};
use tee_service_api::crypto::{aes_decrypt, aes_encrypt, derive_aes_key};

/// Encrypts the provided data using an AES key derived from
/// the provided public key and the enclave's private key
pub fn enclave_ecdh_encrypt(
    pk: &PublicKey,
    data: Vec<u8>,
    nonce: Vec<u8>,
) -> Result<Vec<u8>, anyhow::Error> {
    let sk = get_secp256k1_sk();
    let shared_secret = SharedSecret::new(pk, &sk);
    let aes_key =
        derive_aes_key(&shared_secret).map_err(|e| anyhow!("Error deriving AES key: {:?}", e))?;
    let encrypted_data = aes_encrypt(&aes_key, &data, &nonce)?;
    Ok(encrypted_data)
}

/// Decrypts the provided data using an AES key derived from
/// the provided public key and the enclave's private key
pub fn enclave_ecdh_decrypt(
    pk: &PublicKey,
    data: Vec<u8>,
    nonce: Vec<u8>,
) -> Result<Vec<u8>, anyhow::Error> {
    let sk: SecretKey = get_secp256k1_sk();
    let shared_secret = SharedSecret::new(pk, &sk);
    let aes_key =
        derive_aes_key(&shared_secret).map_err(|e| anyhow!("Error deriving AES key: {:?}", e))?;
    let decrypted_data = aes_decrypt(&aes_key, &data, &nonce)?;
    Ok(decrypted_data)
}
