//! Shared fixtures for the in-crate test suites: a deterministic root key and
//! council keypair, plus builders that assemble a full state over tempdirs
//! and seal envelopes the way the real council tooling would.

use crate::state::CentralizedCustodianState;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use seismic_council_delivery::{
    DeliveryPurpose, SignedDeliveryEnvelope, address_from_pubkey, seal_delivery,
};
use seismic_custodian::Custodian;
use seismic_network_manifest::NetworkId;
use std::path::Path;

pub(crate) const ROOT_KEY: [u8; 32] = [7u8; 32];
pub(crate) const NETWORK: [u8; 32] = [0x11; 32];
/// A valid secp256k1 scalar, usable for every purpose.
pub(crate) const PURPOSE_KEY: [u8; 32] = [0x42; 32];

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

/// Seal one envelope exactly as council tooling would.
pub(crate) fn seal(purpose: DeliveryPurpose, epoch: u64, key: [u8; 32]) -> SignedDeliveryEnvelope {
    seal_delivery(&council_keys().0, &network_id(), purpose, epoch, &key)
}
