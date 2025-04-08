//! This module contains logic for allowing an operator
//! to configure the enclave server, e.g. to set the IP address of existing nodes

use anyhow::anyhow;
use rand::rngs::OsRng;
use rand::TryRngCore;
use secp256k1::rand::rngs::OsRng as Secp256k1Rng;
use secp256k1::Secp256k1;
use seismic_enclave::request_types::boot::*;
use seismic_enclave::rpc::SyncEnclaveApiClient;
use seismic_enclave::{ecdh_decrypt, ecdh_encrypt, nonce::Nonce};
use std::sync::Mutex;
use tracing::info;
use seismic_enclave::coco_as::{Data, HashAlgorithm, AttestationEvalEvidenceRequest};
use kbs_types::Tee;
use seismic_enclave::{get_unsecure_sample_secp256k1_pk, get_unsecure_sample_secp256k1_sk};
// use zeroize::{Zeroize, ZeroizeOnDrop};

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
    pub fn pk(&self) -> secp256k1::PublicKey {
        self.pk.clone()
    }
    pub fn sk(&self) -> secp256k1::SecretKey {
        self.sk.clone()
    }
    pub fn is_compelted(&self) -> bool {
        let guard = self.completed.lock().unwrap();
        *guard
    }

    pub fn mark_completed(&self) {
        let mut completed_guard = self.completed.lock().unwrap();
        *completed_guard = true;

        // Zero the root key
        // TODO: evaluate if this should involve zeroize
        let mut root_gurad = self.km_root_key.lock().unwrap();
        *root_gurad = None;
    }

    // assumes engine handler makes the pk and attested to it
    pub fn retrieve_root_key(
        &self,
        tee: Tee,
        attestation: &Vec<u8>,
        client: &dyn SyncEnclaveApiClient,
    ) -> Result<(), anyhow::Error> {
        let eval_context = AttestationEvalEvidenceRequest {
            evidence: attestation.clone(),
            tee,
            runtime_data: Some(Data::Raw(self.pk().serialize().to_vec())),
            runtime_data_hash_algorithm: Some(HashAlgorithm::Sha256),
            policy_ids: Vec::new(),
        };
        let req = ShareMasterKeyRequest {
            retriever_pk: self.pk(),
            attestation: attestation.clone(),
            eval_context,
        };

        // TODO: How will auth work? enclave x will not have enclave y's jwt
        info!("in boot_retrieve_root_key, beginning client boot_share_root_key call");
        let res = client.boot_share_root_key(req).map_err(
            |e| anyhow!("Error while requesting external service to share root key: {:?}", e),
        )?;
        info!("in boot_retrieve_root_key, finished client boot_share_root_key call");

        // decrypt ciphertext
        let root_key = self.process_share_response(res)?;
        let mut guard = self.km_root_key.lock().unwrap();
        *guard = Some(root_key);
        Ok(())
    }

    pub fn process_share_response(
        &self,
        res: ShareMasterKeyResponse,
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

    // assume engine has already verified the attestation
    pub fn share_root_key(
        &self,
        retriever_pk: &secp256k1::PublicKey,
        existing_root_key: &[u8; 32],
    ) -> Result<(Nonce, Vec<u8>, secp256k1::PublicKey), anyhow::Error> {
        let nonce = Nonce::new_rand();
        let root_key_ciphertext =
            ecdh_encrypt(&retriever_pk, &self.sk(), existing_root_key, nonce.clone())?;
        Ok((nonce, root_key_ciphertext, self.pk()))
    }

    pub fn genesis(&self) -> Result<(), anyhow::Error> {
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
