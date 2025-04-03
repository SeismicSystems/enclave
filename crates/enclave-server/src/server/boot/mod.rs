//! This module contains logic for allowing an operator 
//! to configure the enclave server, e.g. to set the IP address of existing nodes

use seismic_enclave::request_types::boot::*;

use rand::rngs::OsRng;
use rand::TryRngCore;
use secp256k1::Secp256k1;
use secp256k1::rand::rngs::OsRng as Secp256k1Rng;
use seismic_enclave::{ecdh_encrypt, ecdh_decrypt, nonce::Nonce};
use anyhow::anyhow;
// use zeroize::{Zeroize, ZeroizeOnDrop};

pub struct Booter {
    pk: secp256k1::PublicKey,
    sk: secp256k1::SecretKey,
    km_master_key: Option<[u8; 32]>,
}
impl Booter {
    pub fn new() -> Self {
        let secp = Secp256k1::new();
        let (sk, pk) = secp.generate_keypair(&mut Secp256k1Rng);
        Self {
            pk,
            sk,
            km_master_key: None,
        }
    }
    /// Get the master key for the enclave server
    pub fn get_master_key(&self) -> Option<[u8; 32]> {
        self.km_master_key
    }

    // assumes engine handler makes the pk and attested to it
    pub async fn retrieve_master_key(&mut self, url: &str, retriever_pk: &secp256k1::PublicKey, retriever_sk: &secp256k1::SecretKey, nonce: Nonce, attestation: &Vec<u8>) -> Result<(), anyhow::Error> {
        let req = ShareMasterKeyRequest {
            retriever_pk: retriever_pk.clone(),
            attestation: attestation.clone(),
        };

        // TODO: probably modify seismic-enclave rpc to have a method for this
        // How will auth work? enclave x will not have enclave y's jwt
        let http_res = reqwest::Client::new()
            .post(url)
            .json(&req)
            .send().await?;
        let res: ShareMasterKeyResponse = http_res.json().await?;

        // decrypt ciphertext
        let master_key_vec = ecdh_decrypt(&res.sharer_pk, &retriever_sk, &res.master_key_ciphertext, nonce)?;
        let master_key: [u8; 32] = master_key_vec.try_into().map_err(|e| anyhow!("Error casting, master key had unexpected length: {:?}", e))?;

        self.km_master_key = Some(master_key);
        Ok(())
    }

    // assume engine has already verified the attestation
    pub async fn share_master_key(&mut self, retriever_pk: &secp256k1::PublicKey, existing_master_key: &Vec<u8>) -> Result<(Nonce, Vec<u8>, secp256k1::PublicKey), anyhow::Error> {
        let nonce = Nonce::new_rand();
        let master_key_ciphertext = ecdh_encrypt(&retriever_pk, &self.sk, existing_master_key, nonce.clone())?;
        Ok((nonce, master_key_ciphertext, self.pk))
    }

    pub async fn genesis_boot(&mut self) -> Result<(), anyhow::Error> {
        let mut rng = OsRng;
        let mut rng_bytes = [0u8; 32];
        rng.try_fill_bytes(&mut rng_bytes)?;

        self.km_master_key = Some(rng_bytes);
        Ok(())
    }
}