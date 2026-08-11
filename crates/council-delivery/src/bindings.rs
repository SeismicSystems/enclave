//! The AEAD context binding for council key deliveries.
//!
//! Only the encryption AAD lives here — the *signed* digest is EIP-712
//! typed data in [`crate::eip712`], so ordinary Ethereum wallets can produce
//! council signatures. This digest follows the repo's binding convention
//! (`SHA256(domain || network_id || fixed-length fields)`, the purpose
//! hashed as its fixed 1-byte `binding_tag`): it ties the AES-GCM tag to
//! exactly one network, purpose, epoch, and pair of endpoints, so a
//! ciphertext cannot be replayed into a different delivery context even
//! before the signature is checked.

use crate::messages::{DeliveryPayload, DeliveryPurpose};
use seismic_network_manifest::NetworkId;
use sha2::{Digest as _, Sha256};

/// Domain for [`delivery_context_binding`], the AEAD AAD.
const DELIVERY_CTX_DOMAIN: &[u8] = b"seismic-council-key-delivery-ctx-v1:";

/// The AEAD AAD for one delivery: full context, no ciphertext (the
/// ciphertext authenticates itself via its GCM tag; the AAD ties that tag to
/// exactly this network, purpose, epoch, and pair of endpoints).
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

    /// Golden vector: this digest seals every persisted ciphertext (as its
    /// AAD) and must never change.
    #[test]
    fn context_binding_matches_golden_vector() {
        assert_eq!(
            hex::encode(delivery_context_binding(
                &NetworkId::from_bytes([0x11; 32]),
                DeliveryPurpose::TxIo,
                7,
                &[0x22; 33],
                &[0x33; 33],
            )),
            "2ee35c48e0a7eb611240a758a3b8c226b225dec5db62e3ea49714f32235bff11",
        );
    }

    /// Every field perturbs the digest.
    #[test]
    fn context_binding_is_sensitive_to_every_field() {
        let network_id = NetworkId::from_bytes([0x11; 32]);
        let base = delivery_context_binding(
            &network_id,
            DeliveryPurpose::TxIo,
            7,
            &[0x22; 33],
            &[0x33; 33],
        );
        let variants = [
            delivery_context_binding(
                &NetworkId::from_bytes([0x12; 32]),
                DeliveryPurpose::TxIo,
                7,
                &[0x22; 33],
                &[0x33; 33],
            ),
            delivery_context_binding(
                &network_id,
                DeliveryPurpose::RngPrecompile,
                7,
                &[0x22; 33],
                &[0x33; 33],
            ),
            delivery_context_binding(
                &network_id,
                DeliveryPurpose::TxIo,
                8,
                &[0x22; 33],
                &[0x33; 33],
            ),
            delivery_context_binding(
                &network_id,
                DeliveryPurpose::TxIo,
                7,
                &[0x23; 33],
                &[0x33; 33],
            ),
            delivery_context_binding(
                &network_id,
                DeliveryPurpose::TxIo,
                7,
                &[0x22; 33],
                &[0x34; 33],
            ),
        ];
        for (i, variant) in variants.iter().enumerate() {
            assert_ne!(&base, variant, "variant {i} must change the digest");
        }
    }
}
