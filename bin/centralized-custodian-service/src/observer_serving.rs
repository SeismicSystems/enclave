//! Parent-side observer serving: what a custodian needs to answer signed
//! fetches from observer custodians.
//!
//! Present only when `--summit-key-dir` was given. Verification needs only
//! the master *public* key — any child pubkey is derivable from it — so the
//! seed is read once at boot, the pubkey computed, and the seed dropped
//! (zeroized). The root key is kept here for serving because the
//! [`seismic_custodian::Custodian`] deliberately never exposes it.

use anyhow::{Context as _, Result};
use seismic_council_delivery::{
    ObserverFetchRequest, ObserverRejectCode, observer_fetch_signing_payload,
};
use seismic_network_manifest::NetworkId;
use seismic_observer_key::{
    derive_child_public, load_node_seed, master_public_from_seed, observer_namespace_from_chain_id,
    verify,
};
use std::path::Path;
use tracing::info;
use zeroize::Zeroizing;

pub struct ObserverServing {
    master_public: [u8; 32],
    namespace: [u8; 32],
    root_key: Zeroizing<[u8; 32]>,
}

impl ObserverServing {
    /// Load the summit node key, keep only its public key, and remember the
    /// root key for serving. Fatal on a bad keystore by design:
    /// misconfiguration should not silently disable observer serving.
    pub fn load(summit_key_dir: &Path, chain_id: u64, root_key: [u8; 32]) -> Result<Self> {
        let seed = load_node_seed(summit_key_dir)
            .with_context(|| format!("loading summit keystore {}", summit_key_dir.display()))?;
        let master_public = master_public_from_seed(&seed);
        drop(seed); // zeroized; verification never needs it again
        info!(
            master_public = hex::encode(master_public),
            "serving observer custodians for this node key"
        );
        Ok(Self {
            master_public,
            namespace: observer_namespace_from_chain_id(chain_id),
            root_key: Zeroizing::new(root_key),
        })
    }

    pub fn root_key(&self) -> [u8; 32] {
        *self.root_key
    }

    /// Verify one observer fetch: right network, an unconsumed challenge,
    /// and a signature that verifies under the child pubkey derived from
    /// this node's own master key at the claimed index. Any index is
    /// accepted — only the master-key holder can sign as any child, so a
    /// bound would add nothing.
    pub fn verify_fetch(
        &self,
        network_id: &NetworkId,
        nonce: Option<[u8; 32]>,
        request: &ObserverFetchRequest,
        signature: &[u8; 64],
    ) -> Result<(), (ObserverRejectCode, &'static str)> {
        let Some(nonce) = nonce else {
            return Err((
                ObserverRejectCode::MissingChallenge,
                "request a challenge first; each nonce authorizes one fetch",
            ));
        };
        if &request.network_id != network_id.as_bytes() {
            return Err((
                ObserverRejectCode::WrongNetwork,
                "fetch is for a different network",
            ));
        }
        let child_public =
            derive_child_public(&self.master_public, &self.namespace, request.observer_index)
                .map_err(|_| {
                    (
                        ObserverRejectCode::BadSignature,
                        "child key derivation failed",
                    )
                })?;
        let payload = observer_fetch_signing_payload(&nonce, request).map_err(|_| {
            (
                ObserverRejectCode::BadSignature,
                "request could not be encoded for verification",
            )
        })?;
        if !verify(&child_public, &payload, signature) {
            return Err((
                ObserverRejectCode::BadSignature,
                "signature does not verify under the derived child key",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seismic_council_delivery::ObserverQuery;
    use seismic_observer_key::ObserverSigner;

    const SEED: [u8; 32] = [1u8; 32];
    const CHAIN_ID: u64 = 5124;
    const NONCE: [u8; 32] = [0xAB; 32];

    fn serving() -> ObserverServing {
        ObserverServing {
            master_public: master_public_from_seed(&SEED),
            namespace: observer_namespace_from_chain_id(CHAIN_ID),
            root_key: Zeroizing::new([0x07; 32]),
        }
    }

    fn network() -> NetworkId {
        NetworkId::from_bytes([0x11; 32])
    }

    fn signed_request(index: u32, nonce: &[u8; 32]) -> (ObserverFetchRequest, [u8; 64]) {
        let request = ObserverFetchRequest {
            network_id: *network().as_bytes(),
            observer_index: index,
            query: ObserverQuery::RootKey,
        };
        let signer =
            ObserverSigner::derive(&SEED, &observer_namespace_from_chain_id(CHAIN_ID), index);
        let payload = observer_fetch_signing_payload(nonce, &request).unwrap();
        let signature = signer.sign(&payload);
        (request, signature)
    }

    #[test]
    fn valid_fetch_verifies_at_any_index() {
        let serving = serving();
        for index in [0u32, 3, 250_000] {
            let (request, signature) = signed_request(index, &NONCE);
            serving
                .verify_fetch(&network(), Some(NONCE), &request, &signature)
                .unwrap_or_else(|e| panic!("index {index} should verify: {e:?}"));
        }
    }

    #[test]
    fn missing_challenge_is_rejected() {
        let (request, signature) = signed_request(0, &NONCE);
        let err = serving()
            .verify_fetch(&network(), None, &request, &signature)
            .unwrap_err();
        assert_eq!(err.0, ObserverRejectCode::MissingChallenge);
    }

    #[test]
    fn wrong_network_is_rejected() {
        let (request, signature) = signed_request(0, &NONCE);
        let err = serving()
            .verify_fetch(
                &NetworkId::from_bytes([0x99; 32]),
                Some(NONCE),
                &request,
                &signature,
            )
            .unwrap_err();
        assert_eq!(err.0, ObserverRejectCode::WrongNetwork);
    }

    #[test]
    fn wrong_nonce_index_or_tampering_is_rejected() {
        let serving = serving();
        let (request, signature) = signed_request(0, &NONCE);

        // Signature over a different nonce than the connection holds.
        let err = serving
            .verify_fetch(&network(), Some([0xAC; 32]), &request, &signature)
            .unwrap_err();
        assert_eq!(err.0, ObserverRejectCode::BadSignature);

        // Claiming a different index than was signed.
        let mut wrong_index = request.clone();
        wrong_index.observer_index = 1;
        let err = serving
            .verify_fetch(&network(), Some(NONCE), &wrong_index, &signature)
            .unwrap_err();
        assert_eq!(err.0, ObserverRejectCode::BadSignature);

        // Tampering with the query after signing.
        let mut tampered = request.clone();
        tampered.query = ObserverQuery::Envelopes { from_epoch: 1 };
        let err = serving
            .verify_fetch(&network(), Some(NONCE), &tampered, &signature)
            .unwrap_err();
        assert_eq!(err.0, ObserverRejectCode::BadSignature);
    }

    #[test]
    fn foreign_master_key_is_rejected() {
        let serving = serving();
        // Signed by a child of a *different* master key.
        let request = ObserverFetchRequest {
            network_id: *network().as_bytes(),
            observer_index: 0,
            query: ObserverQuery::RootKey,
        };
        let foreign =
            ObserverSigner::derive(&[2u8; 32], &observer_namespace_from_chain_id(CHAIN_ID), 0);
        let payload = observer_fetch_signing_payload(&NONCE, &request).unwrap();
        let signature = foreign.sign(&payload);
        let err = serving
            .verify_fetch(&network(), Some(NONCE), &request, &signature)
            .unwrap_err();
        assert_eq!(err.0, ObserverRejectCode::BadSignature);
    }

    #[test]
    fn wrong_chain_namespace_is_rejected() {
        let serving = serving();
        let request = ObserverFetchRequest {
            network_id: *network().as_bytes(),
            observer_index: 0,
            query: ObserverQuery::RootKey,
        };
        // Right master key, wrong deployment namespace.
        let other_chain = ObserverSigner::derive(&SEED, &observer_namespace_from_chain_id(1), 0);
        let payload = observer_fetch_signing_payload(&NONCE, &request).unwrap();
        let signature = other_chain.sign(&payload);
        let err = serving
            .verify_fetch(&network(), Some(NONCE), &request, &signature)
            .unwrap_err();
        assert_eq!(err.0, ObserverRejectCode::BadSignature);
    }
}
