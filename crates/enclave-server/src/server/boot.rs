//! This module contains logic for allowing an operator
//! to configure the enclave server, e.g. to set the IP address of existing nodes

use anyhow::anyhow;
use kbs_types::Tee;
use rand::rngs::OsRng;
use rand::TryRngCore;
use secp256k1::rand::rngs::OsRng as Secp256k1Rng;
use secp256k1::Secp256k1;
use seismic_enclave::request_types::{ShareRootKeyRequest, ShareRootKeyResponse};
use seismic_enclave::rpc::SyncEnclaveApiClient;
use seismic_enclave::{crypto::Nonce, ecdh_decrypt, ecdh_encrypt};
use seismic_enclave::{get_unsecure_sample_secp256k1_pk, get_unsecure_sample_secp256k1_sk};
use std::sync::Mutex;
use tracing::info;

pub struct Booter {
    // pk and sk are the Booter's keys used to derive encryption keys for communication with other nodes
    pk: secp256k1::PublicKey,
    sk: secp256k1::SecretKey,
    // a root key for the key manager
    km_root_key: Mutex<Option<[u8; 32]>>, // mutex so that that functions can be called without &mut self in the engine
    // tracks whether the booting process has been completed
    completed: Mutex<bool>,
}
impl Booter {
    pub fn new() -> Self {
        let secp = Secp256k1::new();
        let (sk, pk) = secp.generate_keypair(&mut Secp256k1Rng);
        Self {
            pk,
            sk,
            km_root_key: None.into(),
            completed: Mutex::new(false),
        }
    }

    /// a mock booter useful for testing
    /// uses unsecure sample secp256k1 keys instead of a random ones
    pub fn mock() -> Self {
        Self {
            pk: get_unsecure_sample_secp256k1_pk(),
            sk: get_unsecure_sample_secp256k1_sk(),
            km_root_key: None.into(),
            completed: Mutex::new(false),
        }
    }

    /// Get the root key for the enclave server
    pub fn get_root_key(&self) -> Option<[u8; 32]> {
        let guard = self.km_root_key.lock().unwrap();
        guard.clone()
    }
    /// Get the Secp256k1 public key for communication with other nodes
    pub fn pk(&self) -> secp256k1::PublicKey {
        self.pk.clone()
    }
    /// Get the Secp256k1 secret key for communication with other nodes
    pub fn sk(&self) -> secp256k1::SecretKey {
        self.sk.clone()
    }
    /// Get the completion status of the booting process
    /// Used to enable/disable certain engine endpoints
    pub fn is_compelted(&self) -> bool {
        let guard = self.completed.lock().unwrap();
        *guard
    }
    /// Mark the booting process as completed
    pub fn mark_completed(&self) {
        let mut completed_guard = self.completed.lock().unwrap();
        *completed_guard = true;

        // Zero the root key
        let mut root_gurad = self.km_root_key.lock().unwrap();
        *root_gurad = None;
    }

    /// Retrieves the network root key from an existing node and updates this node's root key.
    ///
    /// # Arguments
    ///
    /// * `tee` - The TEE (Trusted Execution Environment) type of the node retrieving the key.
    /// * `attestation` - A byte vector containing the attestation from the existing node about the retriever's public key.
    /// * `client` - A reference to an implementation of the `SyncEnclaveApiClient` trait, used to communicate with the existing node.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the key was successfully retrieved and stored.
    /// * `Err(anyhow::Error)` if the retrieval, decryption, or storage failed.
    pub fn retrieve_root_key(
        &self,
        tee: Tee,
        attestation: &Vec<u8>,
        client: &dyn SyncEnclaveApiClient,
    ) -> Result<(), anyhow::Error> {
        let req = ShareRootKeyRequest {
            retriever_pk: self.pk(),
            tee,
            evidence: attestation.clone(),
        };

        info!("in boot_retrieve_root_key, beginning client boot_share_root_key call");
        let res = client.boot_share_root_key(req).map_err(|e| {
            anyhow!(
                "Error while requesting external service to share root key: {:?}",
                e
            )
        })?;
        info!("in boot_retrieve_root_key, finished client boot_share_root_key call");

        // decrypt ciphertext
        let root_key = self.process_share_response(res)?;
        let mut guard = self.km_root_key.lock().unwrap();
        *guard = Some(root_key);
        Ok(())
    }

    /// Decrypts a shared root key from a `ShareRootKeyResponse`.
    ///
    /// # Returns
    ///
    /// * `Ok([u8; 32])` with the decrypted root key if successful.
    /// * `Err(anyhow::Error)` if decryption fails or if the key is not the expected length.
    pub fn process_share_response(
        &self,
        res: ShareRootKeyResponse,
    ) -> Result<[u8; 32], anyhow::Error> {
        let root_key_vec = ecdh_decrypt(
            &res.sharer_pk,
            &self.sk(),
            &res.root_key_ciphertext,
            res.nonce,
        )?;
        let root_key: [u8; 32] = root_key_vec
            .try_into()
            .map_err(|e| anyhow!("Error casting, root key had unexpected length: {:?}", e))?;
        Ok(root_key)
    }

    /// Encrypts an existing root key for a specified retriever using ECDH.
    ///
    /// # Arguments
    ///
    /// * `retriever_pk` - The public key of the node retrieving the root key.
    /// * `existing_root_key` - A reference to the root key `[u8; 32]` to be encrypted.
    ///
    /// # Returns
    ///
    /// * `Ok((Nonce, Vec<u8>, secp256k1::PublicKey))` containing the nonce, ciphertext, and sharer's public key if successful.
    /// * `Err(anyhow::Error)` if encryption fails.
    pub fn encrypt_root_key(
        &self,
        retriever_pk: &secp256k1::PublicKey,
        existing_root_key: &[u8; 32],
    ) -> Result<(Nonce, Vec<u8>, secp256k1::PublicKey), anyhow::Error> {
        let nonce = Nonce::new_rand();
        let root_key_ciphertext =
            ecdh_encrypt(&retriever_pk, &self.sk(), existing_root_key, nonce.clone())?;
        Ok((nonce, root_key_ciphertext, self.pk()))
    }

    /// Generate a new genesis network root key
    /// root key is generated using OsRng
    pub fn genesis(&self) -> Result<(), anyhow::Error> {
        // FUTURE WORK: consider using key shares instead of OsRng
        let mut rng = OsRng;
        let mut rng_bytes = [0u8; 32];
        rng.try_fill_bytes(&mut rng_bytes)?;

        let mut guard = self.km_root_key.lock().unwrap();
        *guard = Some(rng_bytes);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use seismic_enclave::MockEnclaveClient;

    use super::*;

    #[test]
    fn test_retrieve_root_key_mock() {
        let booter = Booter::new();
        let client = MockEnclaveClient::default();
        let tee = kbs_types::Tee::AzTdxVtpm;
        let res = booter.retrieve_root_key(tee, &Vec::new(), &client);
        assert!(res.is_ok(), "failed to retrieve root key: {:?}", res);
        assert!(booter.get_root_key().is_some(), "root key not set");
        assert!(
            booter.get_root_key().unwrap() == [0u8; 32],
            "root key does not match expected mock value"
        );
    }

    #[test]
    fn test_genesis() {
        let booter = Booter::new();
        assert!(booter.get_root_key().is_none(), "root key should be empty");
        booter.genesis().unwrap();
        assert!(
            booter.get_root_key().is_some(),
            "root key should not be empty"
        );
        let root_key = booter.get_root_key().unwrap();
        booter.genesis().unwrap();
        let new_root_key = booter.get_root_key().unwrap();
        assert!(
            root_key != new_root_key,
            "root key genesis should be random"
        );
    }
}
