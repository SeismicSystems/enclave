//! Shared fixtures for the in-crate test suites: a deterministic root key and
//! council keypair, plus builders that assemble a full state over tempdirs
//! and seal envelopes the way the real council tooling would.

use crate::state::CentralizedCustodianState;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use seismic_council_delivery::{SignedDeliveryEnvelope, address_from_pubkey, seal_delivery};
use seismic_custodian::Custodian;
use seismic_network_manifest::NetworkId;
use std::path::Path;

pub(crate) const ROOT_KEY: [u8; 32] = [7u8; 32];
pub(crate) const NETWORK: [u8; 32] = [0x11; 32];
/// A deliverable epoch root for tests.
pub(crate) const EPOCH_ROOT: [u8; 32] = [0x42; 32];

/// The council's signing key and its Ethereum address (what the node is
/// configured with).
pub(crate) fn council_keys() -> (SecretKey, [u8; 20]) {
    let sk = SecretKey::from_byte_array(&[0x77; 32]).expect("valid scalar");
    let pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk);
    (sk, address_from_pubkey(&pk))
}

pub(crate) fn network_id() -> NetworkId {
    NetworkId::from_bytes(NETWORK)
}

/// A full state whose delivery dir lives under `dir`. Rebuilding over the
/// same `dir` models a service restart.
pub(crate) fn build_state(dir: &Path) -> CentralizedCustodianState {
    CentralizedCustodianState::new(
        Custodian::new(ROOT_KEY),
        dir.join("deliveries"),
        council_keys().1,
        network_id(),
    )
    .expect("build state")
}

/// Seal one epoch-root envelope exactly as council tooling would.
pub(crate) fn seal(epoch: u64, root: [u8; 32]) -> SignedDeliveryEnvelope {
    seal_delivery(&council_keys().0, &network_id(), epoch, &root)
}

/// The parent/observer shared master node seed (an observer holds a copy of
/// its parent's `node_key.pem`).
pub(crate) const MASTER_SEED: [u8; 32] = [1u8; 32];
pub(crate) const CHAIN_ID: u64 = 5124;

/// Write a summit keystore (a `node_key.pem` holding `MASTER_SEED` as hex)
/// under `dir` and return the keystore path.
pub(crate) fn write_summit_keystore(dir: &Path) -> std::path::PathBuf {
    let keystore = dir.join("summit-keys");
    std::fs::create_dir_all(&keystore).expect("create keystore dir");
    std::fs::write(keystore.join("node_key.pem"), hex::encode(MASTER_SEED))
        .expect("write node key");
    keystore
}

/// Parent-side observer serving over the shared fixtures.
pub(crate) fn observer_serving(dir: &Path) -> crate::observer_serving::ObserverServing {
    let keystore = write_summit_keystore(dir);
    crate::observer_serving::ObserverServing::load(&keystore, CHAIN_ID, ROOT_KEY)
        .expect("load observer serving")
}

/// Build one signed `ObserverFetch` the way an observer custodian would,
/// over an already-known challenge nonce.
pub(crate) fn signed_fetch(
    index: u32,
    nonce: &[u8; 32],
    query: seismic_council_delivery::ObserverQuery,
) -> seismic_council_delivery::CouncilRequest {
    let request = seismic_council_delivery::ObserverFetchRequest {
        network_id: NETWORK,
        observer_index: index,
        query,
    };
    let signer = seismic_observer_key::ObserverSigner::derive(
        &MASTER_SEED,
        &seismic_observer_key::observer_namespace_from_chain_id(CHAIN_ID),
        index,
    );
    let payload = seismic_council_delivery::observer_fetch_signing_payload(nonce, &request)
        .expect("encode fetch payload");
    let signature = signer.sign(&payload);
    seismic_council_delivery::CouncilRequest::ObserverFetch { request, signature }
}
