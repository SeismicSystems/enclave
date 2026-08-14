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
/// Domain for [`network_id_from_chain_id`].
const CHAIN_ID_DOMAIN: &[u8] = b"seismic-council-chain-id-v1:";

/// The centralized deployment's network identifier, derived from the EVM
/// chain id instead of a network-manifest hash — the centralized phase has
/// no manifest artifact. Domain-separated so it can never collide with a
/// manifest-derived id, and reproducible by council tooling from the chain
/// id alone. Scopes every delivery signature, payload, and ciphertext to
/// one chain, exactly as the manifest id does for the TDX stack.
pub fn network_id_from_chain_id(chain_id: u64) -> NetworkId {
    let mut hasher = Sha256::new();
    hasher.update(CHAIN_ID_DOMAIN);
    hasher.update(chain_id.to_be_bytes());
    NetworkId::from_bytes(hasher.finalize().into())
}

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

    /// Golden vector: the chain-id-derived network id scopes every
    /// signature and ciphertext; it must never change, and council tooling
    /// must derive the identical value.
    #[test]
    fn chain_id_network_id_matches_golden_vector() {
        assert_eq!(
            hex::encode(network_id_from_chain_id(5124).as_bytes()),
            "cae8a2afaa2c48c2d13164b87f8b3ca8056902bad2cd32a8d457e385b50771a6",
        );
        assert_ne!(
            network_id_from_chain_id(1),
            network_id_from_chain_id(2),
            "distinct chains must scope independently"
        );
    }

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
