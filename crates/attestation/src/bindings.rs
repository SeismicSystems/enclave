//! Helpers for deriving Seismic protocol-binding digests.
//!
//! Every binding is `SHA256(domain || network_id || fixed-length fields ||
//! optional variable tail)`; [`founding_summit_keys_binding`] is the one
//! exception, predating the manifest and so omitting `network_id`. The layout
//! rule: domain string first, then only fixed-length fields (`network_id` 32,
//! nonces 32, compressed secp256k1 points 33, ed25519 32, BLS12-381 MinPk 48,
//! epochs 8 BE), at most one variable-length field and only in tail position —
//! this keeps plain concatenation injective without length prefixes. The fixed
//! sizes are enforced by the signatures. Both sides of the root-key handshake
//! verify the peer's binding against *their own* [`NetworkId`]; mismatch is a
//! hard reject.
//!
//! These helpers return 32-byte SHA-256 digests. Attestation evidence generation
//! takes a 64-byte input, so use [`binding64_from_digest32`] before calling
//! [`crate::generate_evidence`] or [`crate::verify_evidence_with_policy`].

use crate::manifest::NetworkId;
use sha2::{Digest, Sha256};

/// Binding for TxSeismic tx_io public key evidence.
pub fn tx_io_binding(network_id: &NetworkId, tx_io_pk: &[u8; 33], epoch: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"seismic-tx-io-v1:");
    hasher.update(network_id.as_bytes());
    hasher.update(tx_io_pk);
    hasher.update(epoch.to_be_bytes());
    hasher.finalize().into()
}

/// Binding for a root-key bootstrap requester quote.
pub fn root_key_request_binding(
    network_id: &NetworkId,
    nonce_b: &[u8; 32],
    eph_pk_b: &[u8; 33],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"seismic-root-key-req-v1:");
    hasher.update(network_id.as_bytes());
    hasher.update(nonce_b);
    hasher.update(eph_pk_b);
    hasher.finalize().into()
}

/// Binding for a root-key bootstrap responder quote.
pub fn root_key_response_binding(
    network_id: &NetworkId,
    nonce_b: &[u8; 32],
    eph_pk_a: &[u8; 33],
    wrapped: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"seismic-root-key-resp-v1:");
    hasher.update(network_id.as_bytes());
    hasher.update(nonce_b);
    hasher.update(eph_pk_a);
    hasher.update(wrapped);
    hasher.finalize().into()
}

/// Binding for deploy verification of a candidate node.
///
/// An operator checks a freshly provisioned VM before relying on it: they
/// send a fresh `deployment_nonce`, the node quotes over this binding using
/// the `network_id` of the manifest it booted with, and the operator
/// recomputes the binding from its own copies of both fields. A passing
/// quote proves the node holds the expected manifest (right network, not a
/// clone or wrong fork) and minted the evidence for this exact request
/// (`deployment_nonce` is per-request, so captured quotes can't be replayed).
pub fn deploy_verification_binding(
    network_id: &NetworkId,
    deployment_nonce: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"seismic-deploy-v1:");
    hasher.update(network_id.as_bytes());
    hasher.update(deployment_nonce);
    hasher.finalize().into()
}

/// Binding for one founding node's summit keys, harvested before the manifest
/// exists.
///
/// Per node, not per cohort: each founding node generates its own keys and
/// quotes over its own binding, so an N-node ceremony yields N distinct digests
/// and deploy harvests each node separately.
///
/// The pre-manifest `summit-key-holder` generates both keys in RAM and quotes
/// over this binding; deploy's harvest recomputes it from the nonce it sent and
/// the pubkeys it got back, then re-checks it at assemble time against that
/// node's pinned pubkeys. `harvest_nonce` is fresh per request, so an earlier
/// harvest's quote can't be replayed.
///
/// No `network_id`: it doesn't exist yet, since these pubkeys are inputs to the
/// manifest that defines it. Pinning them into the manifest is what supplies the
/// intent binding `network_id` carries elsewhere.
///
/// A passing quote proves measured code generated the keys and holds the
/// corresponding private keys, so possession, TEE custody, and honest generation
/// (no rogue-key choice) all follow from the measurement.
pub fn founding_summit_keys_binding(
    harvest_nonce: &[u8; 32],
    summit_node_pk: &[u8; 32],      // ed25519 node identity
    summit_consensus_pk: &[u8; 48], // BLS12-381 MinPk
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"seismic-founding-keys-v1:");
    hasher.update(harvest_nonce);
    hasher.update(summit_node_pk);
    hasher.update(summit_consensus_pk);
    hasher.finalize().into()
}

/// Expand a shorter protocol digest into the 64-byte attestation input.
pub fn binding64_from_digest32(digest: [u8; 32]) -> [u8; 64] {
    let mut binding = [0u8; 64];
    binding[..32].copy_from_slice(&digest);
    binding
}

#[cfg(test)]
mod tests {
    use super::*;

    // Stable wire-format vectors: any change to a domain string or field
    // layout breaks cross-implementation transcript verification, so these
    // digests must never change. Cross-checked against an independent
    // computation (python hashlib over the concatenated layout).
    #[test]
    fn binding_helpers_are_stable() {
        let network_id = NetworkId::from_bytes([0x11; 32]);
        let nonce = [0x33; 32];

        let mut tx_io_pk = [0x22; 33];
        tx_io_pk[0] = 0x02;
        let mut eph_pk_b = [0x44; 33];
        eph_pk_b[0] = 0x02;
        let mut eph_pk_a = [0x55; 33];
        eph_pk_a[0] = 0x02;

        assert_eq!(
            hex::encode(tx_io_binding(&network_id, &tx_io_pk, 7)),
            "226d77df41e0a51c6173fdbc58df2302aeea627a9051c051afc861ebc4a16f46"
        );
        assert_eq!(
            hex::encode(root_key_request_binding(&network_id, &nonce, &eph_pk_b)),
            "1c4e440a61093dcbc3574a938cc545b8807cdd87529202e6761d01c58aae0184"
        );
        assert_eq!(
            hex::encode(root_key_response_binding(
                &network_id,
                &nonce,
                &eph_pk_a,
                b"wrapped"
            )),
            "2ac4df85ca3f07ca8f279bd6aea9db824e8481f776178e051439c92118782eee"
        );
        assert_eq!(
            hex::encode(deploy_verification_binding(&network_id, &[0x66; 32])),
            "16a53bcb2d1421951a830a1308bca525b8ecfbf96fc89ad6152cdbfce4777eb9"
        );
        assert_eq!(
            hex::encode(founding_summit_keys_binding(
                &[0x77; 32],
                &[0x88; 32],
                &[0x99; 48]
            )),
            "8973b984dc10f809ebfaacdcad64b8cc5a647cf24e4bc27b3833cc234a9290e5"
        );
    }

    #[test]
    fn bindings_diverge_across_networks() {
        let nonce = [0x33; 32];
        let mut eph_pk_b = [0x44; 33];
        eph_pk_b[0] = 0x02;

        let binding_net_a =
            root_key_request_binding(&NetworkId::from_bytes([0xAA; 32]), &nonce, &eph_pk_b);
        let binding_net_b =
            root_key_request_binding(&NetworkId::from_bytes([0xBB; 32]), &nonce, &eph_pk_b);
        assert_ne!(binding_net_a, binding_net_b);
    }

    // The harvest nonce plays the anti-replay role `network_id` plays in the
    // post-founding bindings: one node's keys harvested twice must produce two
    // different bindings, so an earlier harvest's quote can't be replayed.
    #[test]
    fn bindings_diverge_across_harvests() {
        let node_pk = [0x88; 32];
        let consensus_pk = [0x99; 48];

        let harvest_a = founding_summit_keys_binding(&[0xAA; 32], &node_pk, &consensus_pk);
        let harvest_b = founding_summit_keys_binding(&[0xBB; 32], &node_pk, &consensus_pk);
        assert_ne!(harvest_a, harvest_b);
    }

    #[test]
    fn binding64_zero_pads_digest32() {
        let digest = [7u8; 32];
        let binding = binding64_from_digest32(digest);
        assert_eq!(&binding[..32], &digest);
        assert_eq!(&binding[32..], &[0u8; 32]);
    }
}
