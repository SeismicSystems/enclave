//! Binding digests for council key deliveries.
//!
//! Same layout discipline as `seismic_attestation::bindings` (which this
//! crate deliberately does not depend on): every digest is
//! `SHA256(domain || network_id || fixed-length fields || optional variable
//! tail)`, with the variable-length field only in tail position so plain
//! concatenation stays injective without length prefixes. The purpose is
//! hashed as its fixed 1-byte `binding_tag`, not its label.

use crate::messages::{DeliveryPayload, DeliveryPurpose};
use seismic_network_manifest::NetworkId;
use sha2::{Digest as _, Sha256};

/// Domain for [`delivery_context_binding`], the AEAD AAD.
const DELIVERY_CTX_DOMAIN: &[u8] = b"seismic-council-key-delivery-ctx-v1:";
/// Domain for [`delivery_binding`], the council-signed digest.
const DELIVERY_DOMAIN: &[u8] = b"seismic-council-key-delivery-v1:";

/// The AEAD AAD for one delivery: full context, no ciphertext (the ciphertext
/// authenticates itself via its GCM tag; the AAD ties that tag to exactly this
/// network, purpose, epoch, and key pair of endpoints).
pub fn delivery_context_binding(
    network_id: &NetworkId,
    purpose: DeliveryPurpose,
    epoch: u64,
    sender_eph_pk: &[u8; 33],
    inbox_pk: &[u8; 33],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DELIVERY_CTX_DOMAIN);
    hasher.update(network_id.as_bytes());
    hasher.update([purpose.binding_tag()]);
    hasher.update(epoch.to_be_bytes());
    hasher.update(sender_eph_pk);
    hasher.update(inbox_pk);
    hasher.finalize().into()
}

/// The digest the council signs: the full context PLUS the ciphertext tail,
/// so a valid signature cannot be re-attached to a swapped re-encryption of
/// different key bytes.
pub fn delivery_binding(
    network_id: &NetworkId,
    purpose: DeliveryPurpose,
    epoch: u64,
    sender_eph_pk: &[u8; 33],
    inbox_pk: &[u8; 33],
    encrypted_key: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DELIVERY_DOMAIN);
    hasher.update(network_id.as_bytes());
    hasher.update([purpose.binding_tag()]);
    hasher.update(epoch.to_be_bytes());
    hasher.update(sender_eph_pk);
    hasher.update(inbox_pk);
    hasher.update(encrypted_key);
    hasher.finalize().into()
}

/// [`delivery_binding`] over a payload's own fields — what verification
/// recomputes from a received envelope.
pub fn payload_binding(payload: &DeliveryPayload) -> [u8; 32] {
    delivery_binding(
        &NetworkId::from_bytes(payload.network_id),
        payload.purpose,
        payload.epoch,
        &payload.sender_eph_pk,
        &payload.inbox_pk,
        &payload.encrypted_key,
    )
}

/// [`delivery_context_binding`] over a payload's own fields.
pub fn payload_context_binding(payload: &DeliveryPayload) -> [u8; 32] {
    delivery_context_binding(
        &NetworkId::from_bytes(payload.network_id),
        payload.purpose,
        payload.epoch,
        &payload.sender_eph_pk,
        &payload.inbox_pk,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (NetworkId, [u8; 33], [u8; 33], Vec<u8>) {
        (
            NetworkId::from_bytes([0x11; 32]),
            [0x22; 33],
            [0x33; 33],
            vec![0x44; 60],
        )
    }

    /// Golden vectors: these digests are persisted implicitly (signatures over
    /// them live on disk and with the council) and must never change.
    #[test]
    fn binding_digests_match_golden_vectors() {
        let (network_id, sender, inbox, ct) = fixture();
        assert_eq!(
            hex::encode(delivery_context_binding(
                &network_id,
                DeliveryPurpose::TxIo,
                7,
                &sender,
                &inbox,
            )),
            "2ee35c48e0a7eb611240a758a3b8c226b225dec5db62e3ea49714f32235bff11",
        );
        assert_eq!(
            hex::encode(delivery_binding(
                &network_id,
                DeliveryPurpose::TxIo,
                7,
                &sender,
                &inbox,
                &ct,
            )),
            "f9517536fba2841f95798aadddc3bd3afa7efb59f1c9d0bf07d7f02ee312e73c",
        );
    }

    /// Every field perturbs the digest.
    #[test]
    fn binding_is_sensitive_to_every_field() {
        let (network_id, sender, inbox, ct) = fixture();
        let base = delivery_binding(&network_id, DeliveryPurpose::TxIo, 7, &sender, &inbox, &ct);
        let variants = [
            delivery_binding(
                &NetworkId::from_bytes([0x12; 32]),
                DeliveryPurpose::TxIo,
                7,
                &sender,
                &inbox,
                &ct,
            ),
            delivery_binding(
                &network_id,
                DeliveryPurpose::RngPrecompile,
                7,
                &sender,
                &inbox,
                &ct,
            ),
            delivery_binding(&network_id, DeliveryPurpose::TxIo, 8, &sender, &inbox, &ct),
            delivery_binding(
                &network_id,
                DeliveryPurpose::TxIo,
                7,
                &[0x23; 33],
                &inbox,
                &ct,
            ),
            delivery_binding(
                &network_id,
                DeliveryPurpose::TxIo,
                7,
                &sender,
                &[0x34; 33],
                &ct,
            ),
            delivery_binding(
                &network_id,
                DeliveryPurpose::TxIo,
                7,
                &sender,
                &inbox,
                &[0x45; 60],
            ),
        ];
        for (i, variant) in variants.iter().enumerate() {
            assert_ne!(&base, variant, "variant {i} must change the digest");
        }
        // And the two domains never collide on identical fields.
        assert_ne!(
            delivery_context_binding(&network_id, DeliveryPurpose::TxIo, 7, &sender, &inbox),
            delivery_binding(&network_id, DeliveryPurpose::TxIo, 7, &sender, &inbox, &[]),
        );
    }
}
