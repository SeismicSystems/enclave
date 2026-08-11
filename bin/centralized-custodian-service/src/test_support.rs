//! Shared fixtures for the in-crate test suites: a deterministic root key and
//! council keypair, plus builders that assemble a full state over tempdirs
//! and seal envelopes the way the real council tooling would.

use crate::state::CentralizedCustodianState;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use seismic_council_delivery::{DeliveryPurpose, SignedDeliveryEnvelope, seal_delivery};
use seismic_custodian::Custodian;
use seismic_network_manifest::NetworkId;
use std::path::Path;

pub(crate) const ROOT_KEY: [u8; 32] = [7u8; 32];
pub(crate) const NETWORK: [u8; 32] = [0x11; 32];
/// A valid secp256k1 scalar, usable for every purpose.
pub(crate) const PURPOSE_KEY: [u8; 32] = [0x42; 32];

pub(crate) fn council_keys() -> (SecretKey, PublicKey) {
    let sk = SecretKey::from_byte_array(&[0x77; 32]).expect("valid scalar");
    let pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk);
    (sk, pk)
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

/// Seal one envelope exactly as council tooling would: to the inbox key that
/// every holder of [`ROOT_KEY`] derives.
pub(crate) fn seal(purpose: DeliveryPurpose, epoch: u64, key: [u8; 32]) -> SignedDeliveryEnvelope {
    let inbox_pk = Custodian::new(ROOT_KEY).get_council_inbox_pk();
    seal_delivery(
        &council_keys().0,
        &network_id(),
        purpose,
        epoch,
        &inbox_pk,
        &key,
    )
    .expect("seal delivery")
}
