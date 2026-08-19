//! Sealing and verifying council delivery envelopes.
//!
//! An envelope is a plaintext payload under an Ethereum-wallet signature
//! (65-byte recoverable ECDSA over the EIP-712 digest in [`crate::eip712`],
//! which commits to the key via keccak-256). Confidentiality is not this
//! layer's job: the centralized phase runs among known operators, and the
//! deployment puts a TLS terminator or tunnel in front of the council port.
//! At rest, an envelope file is itself a secret.
//!
//! [`seal_delivery`] signs with a locally held key (tests, script-driven
//! councils). A wallet-driven council instead has the wallet sign
//! [`crate::eip712::typed_data_json`] and attaches the wallet's signature to
//! the payload — the digest is identical, and sealing is deterministic
//! (RFC 6979), so equal payloads always yield byte-identical envelopes.
//!
//! [`verify_delivery`] is pure per-envelope validation; epoch sequencing and
//! conflict rules live with the caller's state, not here.

use crate::eip712::{address_from_pubkey, payload_digest};
use crate::messages::{DeliveryPurpose, SignedDeliveryEnvelope};
use anyhow::{Context as _, Result};
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::{Message, Secp256k1, SecretKey};
use seismic_network_manifest::NetworkId;
use zeroize::Zeroizing;

use crate::messages::DeliveryPayload;

/// Build and sign one delivery with a locally held council key. Runs on the
/// council side; the custodian never calls this.
pub fn seal_delivery(
    council_sk: &SecretKey,
    network_id: &NetworkId,
    purpose: DeliveryPurpose,
    epoch: u64,
    purpose_key: &[u8; 32],
) -> SignedDeliveryEnvelope {
    let payload = DeliveryPayload {
        network_id: *network_id.as_bytes(),
        purpose,
        epoch,
        key: *purpose_key,
    };
    let signature = sign_payload(council_sk, &payload);
    SignedDeliveryEnvelope { payload, signature }
}

/// Ethereum-style recoverable signature over the payload's EIP-712 digest:
/// `r(32) || s(32) || v` with `v` in {27, 28}, byte-compatible with what a
/// wallet returns for [`crate::eip712::typed_data_json`].
fn sign_payload(council_sk: &SecretKey, payload: &DeliveryPayload) -> [u8; 65] {
    let digest = payload_digest(payload);
    let (recovery_id, sig64) = Secp256k1::signing_only()
        .sign_ecdsa_recoverable(&Message::from_digest(digest), council_sk)
        .serialize_compact();
    let mut signature = [0u8; 65];
    signature[..64].copy_from_slice(&sig64);
    signature[64] = 27 + i32::from(recovery_id) as u8;
    signature
}

/// Recover the Ethereum address that signed the payload's EIP-712 digest.
/// Accepts `v` as 27/28 (wallets) or 0/1 (raw recovery ids).
fn recover_signer(envelope: &SignedDeliveryEnvelope) -> Option<[u8; 20]> {
    let v = envelope.signature[64];
    let recovery_id = RecoveryId::try_from(i32::from(match v {
        27 | 28 => v - 27,
        0 | 1 => v,
        _ => return None,
    }))
    .ok()?;
    let signature =
        RecoverableSignature::from_compact(&envelope.signature[..64], recovery_id).ok()?;
    let digest = payload_digest(&envelope.payload);
    let recovered = Secp256k1::verification_only()
        .recover_ecdsa(&Message::from_digest(digest), &signature)
        .ok()?;
    Some(address_from_pubkey(&recovered))
}

/// Why an envelope failed verification. Sanitized-by-construction: variants
/// carry no payload detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum VerifyDeliveryError {
    #[error("delivery is for a different network")]
    WrongNetwork,
    #[error("delivery signature does not recover to the council address")]
    BadSignature,
}

/// Verify one envelope against the council address and this network, and
/// return the purpose key. The signed digest commits to the key bytes, so a
/// verified envelope's key is exactly what the council authorized.
pub fn verify_delivery(
    envelope: &SignedDeliveryEnvelope,
    council_address: &[u8; 20],
    network_id: &NetworkId,
) -> Result<Zeroizing<[u8; 32]>, VerifyDeliveryError> {
    let payload = &envelope.payload;
    if &payload.network_id != network_id.as_bytes() {
        return Err(VerifyDeliveryError::WrongNetwork);
    }
    let signer = recover_signer(envelope).ok_or(VerifyDeliveryError::BadSignature)?;
    if &signer != council_address {
        return Err(VerifyDeliveryError::BadSignature);
    }
    Ok(Zeroizing::new(payload.key))
}

/// The one CBOR encoding of an envelope, used for persistence and for the
/// byte-identity redelivery check. ciborium encodes a fixed struct
/// deterministically, so equal envelopes always produce equal bytes. The
/// bytes contain the plaintext key: treat them as a secret.
pub fn canonical_envelope_bytes(envelope: &SignedDeliveryEnvelope) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    ciborium::into_writer(envelope, &mut *bytes).context("encoding delivery envelope")?;
    Ok(bytes)
}

/// Inverse of [`canonical_envelope_bytes`], for loading persisted envelopes.
pub fn envelope_from_bytes(bytes: &[u8]) -> Result<SignedDeliveryEnvelope> {
    ciborium::from_reader(bytes).context("decoding delivery envelope")
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::PublicKey;

    fn council() -> (SecretKey, [u8; 20]) {
        let sk = SecretKey::from_byte_array(&[0x77; 32]).unwrap();
        let pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk);
        (sk, address_from_pubkey(&pk))
    }

    const NETWORK: [u8; 32] = [0x11; 32];
    const PURPOSE_KEY: [u8; 32] = [0x42; 32];

    fn sealed(epoch: u64) -> SignedDeliveryEnvelope {
        let (council_sk, _) = council();
        seal_delivery(
            &council_sk,
            &NetworkId::from_bytes(NETWORK),
            DeliveryPurpose::TxIo,
            epoch,
            &PURPOSE_KEY,
        )
    }

    #[test]
    fn seal_then_verify_roundtrips_and_is_deterministic() {
        let (_, council_address) = council();
        let envelope = sealed(1);
        let key =
            verify_delivery(&envelope, &council_address, &NetworkId::from_bytes(NETWORK)).unwrap();
        assert_eq!(*key, PURPOSE_KEY);
        // Deterministic sealing: the identical payload re-seals to the
        // byte-identical envelope, which is what makes retries idempotent.
        assert_eq!(sealed(1), envelope);
        assert_eq!(
            *canonical_envelope_bytes(&sealed(1)).unwrap(),
            *canonical_envelope_bytes(&envelope).unwrap()
        );
    }

    #[test]
    fn verify_rejects_wrong_network() {
        let (_, council_address) = council();
        let err = verify_delivery(
            &sealed(1),
            &council_address,
            &NetworkId::from_bytes([0x99; 32]),
        )
        .unwrap_err();
        assert_eq!(err, VerifyDeliveryError::WrongNetwork);
    }

    #[test]
    fn verify_rejects_non_council_signer() {
        let impostor = SecretKey::from_byte_array(&[0x66; 32]).unwrap();
        let envelope = seal_delivery(
            &impostor,
            &NetworkId::from_bytes(NETWORK),
            DeliveryPurpose::TxIo,
            1,
            &PURPOSE_KEY,
        );
        let (_, council_address) = council();
        let err = verify_delivery(&envelope, &council_address, &NetworkId::from_bytes(NETWORK))
            .unwrap_err();
        assert_eq!(err, VerifyDeliveryError::BadSignature);
    }

    /// Tampering with any signed field after sealing breaks the signature —
    /// including the key bytes, which the digest commits to.
    #[test]
    fn verify_rejects_tampered_fields() {
        let (_, council_address) = council();
        let network_id = NetworkId::from_bytes(NETWORK);

        let mut key_swap = sealed(1);
        key_swap.payload.key = [0x43; 32];
        let mut epoch_bump = sealed(1);
        epoch_bump.payload.epoch = 2;
        let mut purpose_swap = sealed(1);
        purpose_swap.payload.purpose = DeliveryPurpose::Snapshot;

        for (label, tampered) in [
            ("key swap", key_swap),
            ("epoch bump", epoch_bump),
            ("purpose swap", purpose_swap),
        ] {
            let err = verify_delivery(&tampered, &council_address, &network_id).unwrap_err();
            assert_eq!(err, VerifyDeliveryError::BadSignature, "{label}");
        }
    }

    /// End-to-end Ethereum-wallet compatibility: this signature was produced
    /// by foundry (`cast wallet sign --data '<typed_data_json(payload)>'`
    /// with private key 0x77..77, address
    /// 0xAe72A48c1a36bd18Af168541c53037965d26e4A8), not by this crate. The
    /// wallet signed only the key's commitment, yet the envelope carrying
    /// the plaintext key must verify — pinning that a stock wallet signing
    /// [`crate::eip712::typed_data_json`] yields an envelope this code
    /// accepts, and that local signing is byte-identical.
    #[test]
    fn wallet_produced_signature_recovers_to_the_council_address() {
        let payload = DeliveryPayload {
            network_id: NETWORK,
            purpose: DeliveryPurpose::TxIo,
            epoch: 7,
            key: [0x44; 32],
        };
        let cast_signature = hex::decode(
            "3d6a8e585b1a7dfdcc272860162bcf142ccf60b4f3cd8ba6714b416d91bed2d8\
             0bc8fc0c3e445e46b0c1821455bb28b1305aad519c90c0ea723c7d269c90d7171c",
        )
        .unwrap();
        let envelope = SignedDeliveryEnvelope {
            payload: payload.clone(),
            signature: cast_signature.try_into().unwrap(),
        };
        let (council_sk, council_address) = council();
        assert_eq!(
            hex::encode(council_address),
            "ae72a48c1a36bd18af168541c53037965d26e4a8"
        );
        assert_eq!(recover_signer(&envelope), Some(council_address));
        // Local signing produces the exact same signature bytes.
        assert_eq!(sign_payload(&council_sk, &payload), envelope.signature);
    }

    #[test]
    fn canonical_bytes_roundtrip() {
        let envelope = sealed(1);
        let bytes = canonical_envelope_bytes(&envelope).unwrap();
        assert_eq!(envelope_from_bytes(&bytes).unwrap(), envelope);
        // A different key produces a different envelope (commitment + bytes).
        let (council_sk, _) = council();
        let other = seal_delivery(
            &council_sk,
            &NetworkId::from_bytes(NETWORK),
            DeliveryPurpose::TxIo,
            1,
            &[0x43; 32],
        );
        assert_ne!(*bytes, *canonical_envelope_bytes(&other).unwrap());
    }
}
