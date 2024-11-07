pub mod handlers;

use anyhow::{anyhow, Result};
use secp256k1::ecdh::SharedSecret;
use secp256k1::{PublicKey, SecretKey};
use tee_service_api::crypto::{aes_encrypt, aes_decrypt, derive_aes_key};

pub fn ecdh_encrypt(pk: &PublicKey, sk: &SecretKey, data: Vec<u8>, nonce: u64) -> Result<Vec<u8>, anyhow::Error> {
    let shared_secret = SharedSecret::new(pk, sk);
    let aes_key = derive_aes_key(&shared_secret)
        .map_err(|e| anyhow!("Error while deriving AES key: {:?}", e))?;
    let encrypted_data = aes_encrypt(&aes_key, &data, nonce);
    Ok(encrypted_data)
} 

pub fn ecdh_decrypt(pk: &PublicKey, sk: &SecretKey, data: Vec<u8>, nonce: u64) -> Result<Vec<u8>, anyhow::Error> {
    let shared_secret = SharedSecret::new(pk, sk);
    let aes_key = derive_aes_key(&shared_secret)
        .map_err(|e| anyhow!("Error while deriving AES key: {:?}", e))?;
    let decrypted_data = aes_decrypt(&aes_key, &data, nonce)?;
    Ok(decrypted_data)
}