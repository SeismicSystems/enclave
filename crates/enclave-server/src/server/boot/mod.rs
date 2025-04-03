//! This module contains logic for allowing an operator
//! to configure the enclave server, e.g. to set the IP address of existing nodes

use std::net::SocketAddr;

use seismic_enclave::request_types::boot::*;

use anyhow::anyhow;
use rand::rngs::OsRng;
use rand::TryRngCore;
use secp256k1::rand::rngs::OsRng as Secp256k1Rng;
use secp256k1::Secp256k1;
use seismic_enclave::rpc::SyncEnclaveApiClient;
use seismic_enclave::{ecdh_decrypt, ecdh_encrypt, nonce::Nonce};
use std::sync::Mutex;
// use zeroize::{Zeroize, ZeroizeOnDrop};

use seismic_enclave::EnclaveClient;

pub struct Booter {
    // pk and sk are the Booter's keys used to derive encryption keys for communication with other nodes
    pk: secp256k1::PublicKey,
    sk: secp256k1::SecretKey,
    // a master key for the key manager
    km_master_key: Mutex<Option<[u8; 32]>>, // mutex so that that functions can be called without &mut self in the engine
}
impl Booter {
    pub fn new() -> Self {
        let secp = Secp256k1::new();
        let (sk, pk) = secp.generate_keypair(&mut Secp256k1Rng);
        Self {
            pk,
            sk,
            km_master_key: None.into(),
        }
    }
    /// Get the master key for the enclave server
    pub fn get_master_key(&self) -> Option<[u8; 32]> {
        let guard = self.km_master_key.lock().unwrap();
        guard.clone()
    }

    // assumes engine handler makes the pk and attested to it
    pub fn retrieve_master_key(
        &self,
        addr: SocketAddr,
        attestation: &Vec<u8>,
    ) -> Result<(), anyhow::Error> {
        let req = ShareMasterKeyRequest {
            retriever_pk: self.pk.clone(),
            attestation: attestation.clone(),
        };

        // TODO: How will auth work? enclave x will not have enclave y's jwt
        let client = EnclaveClient::mock(addr.ip().to_string(), addr.port())?;
        let res = client.boot_share_master_key(req)?;

        // decrypt ciphertext
        let master_key_vec = ecdh_decrypt(
            &res.sharer_pk,
            &self.sk,
            &res.master_key_ciphertext,
            res.nonce,
        )?;
        let master_key: [u8; 32] = master_key_vec
            .try_into()
            .map_err(|e| anyhow!("Error casting, master key had unexpected length: {:?}", e))?;

        let mut guard = self.km_master_key.lock().unwrap();
        *guard = Some(master_key);
        Ok(())
    }

    // assume engine has already verified the attestation
    pub fn share_master_key(
        &self,
        retriever_pk: &secp256k1::PublicKey,
        existing_master_key: &[u8; 32],
    ) -> Result<(Nonce, Vec<u8>, secp256k1::PublicKey), anyhow::Error> {
        let nonce = Nonce::new_rand();
        let master_key_ciphertext =
            ecdh_encrypt(&retriever_pk, &self.sk, existing_master_key, nonce.clone())?;
        Ok((nonce, master_key_ciphertext, self.pk))
    }

    pub fn genesis_boot(&self) -> Result<(), anyhow::Error> {
        let mut rng = OsRng;
        let mut rng_bytes = [0u8; 32];
        rng.try_fill_bytes(&mut rng_bytes)?;

        let mut guard = self.km_master_key.lock().unwrap();
        *guard = Some(rng_bytes);
        Ok(())
    }
}
