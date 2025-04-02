//! This module contains logic for allowing an operator 
//! to configure the enclave server, e.g. to set the IP address of existing nodes

use seismic_enclave::request_types::boot::*;

use rand::rngs::OsRng;
use rand::TryRngCore;
use secp256k1::Secp256k1;
use secp256k1::rand::rngs::OsRng as Secp256k1Rng;

pub struct Booter {
    master_key: Option<[u8; 32]>,
}
impl Booter {
    pub fn new() -> Self {
        Self {
            master_key: None,
        }
    }
    /// Get the master key for the enclave server
    pub fn get_master_key(&self) -> Option<[u8; 32]> {
        self.master_key
    }

    // assumes engine handler makes the pk and attested to it
    pub async fn retrieve_master_key(&mut self, url: &str, retriever_pk: &secp256k1::PublicKey, retriever_sk: &secp256k1::SecretKey, attestation: &Vec<u8>) -> Result<(), anyhow::Error> {

        let req = ShareMasterKeyRequest {
            retriever_pk: retriever_pk.clone(),
            attestation: attestation.clone(),
        };

        // TODO: probably modify seismic-enclave rpc to have a method for this
        // How will auth work? enclave x will not have enclave y's jwt
        let res = reqwest::Client::new()
            .post(url)
            .json(&req)
            .send().await?;
        let real_res: ShareMasterKeyResponse = res.json().await?;

        // TODO: decrypt ciphertext
        // let master_key: [u8; 32] = decrypt(real_res.master_key_ciphertext, retriever_sk, sharer_pk)?;
        let master_key = [0u8; 32];

        self.master_key = Some(master_key);
        Ok(())
    }

    // assume engine has already verified the attestation
    pub async fn share_master_key(&mut self, sharer_pk: &secp256k1::PublicKey) -> Result<(Vec<u8>, secp256k1::PublicKey), anyhow::Error> {
        // assume engine has already verified the attestation
        let secp = Secp256k1::new();
        let (sharer_sk, sharer_pk) = secp.generate_keypair(&mut Secp256k1Rng);
        
        // TODO:  derive encryption key, encrypt master key
        let master_key_ciphertext = [0u8; 32];
        let vec: Vec<u8> = master_key_ciphertext.to_vec();
        
        Ok((vec, sharer_pk))
    }

    pub async fn genesis_boot(&mut self) -> Result<(), anyhow::Error> {
        let mut rng = OsRng;
        let mut rng_bytes = [0u8; 32];
        rng.try_fill_bytes(&mut rng_bytes)?;

        self.master_key = Some(rng_bytes);
        Ok(())
    }
}