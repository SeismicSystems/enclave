//! Sealing and opening council delivery envelopes.
//!
//! A sealed envelope is independently authenticated and confidential:
//! the council's compact ECDSA signature covers the full payload including
//! the ciphertext (via [`bindings::delivery_binding`]), and the 32-byte
//! purpose key is AEAD-encrypted to the custodian's inbox key with the
//! context digest as AAD. Verification never requires the plaintext, so
//! envelopes persist verbatim and are re-verified on every load.
//!
//! [`open_delivery`] is pure per-envelope validation; epoch sequencing and
//! conflict rules live with the caller's state, not here.

use crate::bindings::{payload_binding, payload_context_binding};
use crate::messages::{DeliveryPurpose, SignedDeliveryEnvelope};
use anyhow::{Context as _, Result, anyhow};
use rand::{TryRngCore as _, rngs::OsRng};
use secp256k1::ecdh::SharedSecret;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use seismic_crypto::{
    AESGCM_NONCE_SIZE, AesKeyDomain, Nonce, aes_decrypt_aead, aes_encrypt_aead, derive_aes_key,
};
use seismic_network_manifest::NetworkId;
use zeroize::{Zeroize as _, Zeroizing};

use crate::messages::DeliveryPayload;

/// A fresh council-side ephemeral ECDH keypair for one envelope.
///
/// Local copy of `seismic_custodian::EphemeralKeypair` — this crate is linked
/// by off-node signer tooling and deliberately does not depend on the
/// key-holding custodian crate.
pub struct EphemeralKeypair {
    pub sk: SecretKey,
    pub pk: PublicKey,
}

impl EphemeralKeypair {
    /// Draw the scalar from the OS CSPRNG, retrying on the negligible chance
    /// of an out-of-range scalar (secp256k1 0.30's own generator wants a
    /// rand 0.8 RNG; the workspace is on rand 0.9).
    pub fn generate() -> Self {
        let secp = Secp256k1::new();
        loop {
            let mut bytes = [0u8; 32];
            OsRng
                .try_fill_bytes(&mut bytes)
                .expect("OS RNG must produce ephemeral key material");
            if let Ok(sk) = SecretKey::from_byte_array(&bytes) {
                let pk = PublicKey::from_secret_key(&secp, &sk);
                return Self { sk, pk };
            }
        }
    }
}

/// Seal one purpose key for the custodian: encrypt it to `inbox_pk` under a
/// fresh ephemeral, then sign the complete payload with the council key.
/// Runs on the council side; the custodian never calls this.
pub fn seal_delivery(
    council_sk: &SecretKey,
    network_id: &NetworkId,
    purpose: DeliveryPurpose,
    epoch: u64,
    inbox_pk: &PublicKey,
    purpose_key: &[u8; 32],
) -> Result<SignedDeliveryEnvelope> {
    let eph = EphemeralKeypair::generate();
    let shared = SharedSecret::new(inbox_pk, &eph.sk);
    let aes_key = derive_aes_key(&shared, AesKeyDomain::CouncilKeyDelivery)
        .map_err(|e| anyhow!("deriving delivery AES key: {e}"))?;

    let mut payload = DeliveryPayload {
        network_id: *network_id.as_bytes(),
        purpose,
        epoch,
        sender_eph_pk: eph.pk.serialize(),
        inbox_pk: inbox_pk.serialize(),
        encrypted_key: Vec::new(),
    };
    let aad = payload_context_binding(&payload);

    let nonce = Nonce::new_rand();
    let ciphertext = aes_encrypt_aead(&aes_key, purpose_key, nonce.clone(), &aad)
        .context("AEAD-sealing purpose key")?;
    let mut encrypted_key = Vec::with_capacity(AESGCM_NONCE_SIZE + ciphertext.len());
    encrypted_key.extend_from_slice(&nonce.0);
    encrypted_key.extend_from_slice(&ciphertext);
    payload.encrypted_key = encrypted_key;

    let digest = payload_binding(&payload);
    let signature = Secp256k1::signing_only()
        .sign_ecdsa(&Message::from_digest(digest), council_sk)
        .serialize_compact();

    Ok(SignedDeliveryEnvelope { payload, signature })
}

/// Why an envelope failed to open. Sanitized-by-construction: variants carry
/// no payload detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OpenDeliveryError {
    #[error("delivery is for a different network")]
    WrongNetwork,
    #[error("delivery is sealed to a different inbox key")]
    WrongRecipient,
    #[error("delivery signature is not by the council key")]
    BadSignature,
    #[error("delivery ciphertext failed to open")]
    DecryptFailed,
}

/// Verify one envelope against the council key and this custodian's identity,
/// then decrypt the purpose key. Checks recipient and network before the
/// signature so responses distinguish misdirection from forgery.
pub fn open_delivery(
    envelope: &SignedDeliveryEnvelope,
    council_pk: &PublicKey,
    network_id: &NetworkId,
    inbox_sk: &SecretKey,
    inbox_pk: &PublicKey,
) -> Result<Zeroizing<[u8; 32]>, OpenDeliveryError> {
    let payload = &envelope.payload;
    if &payload.network_id != network_id.as_bytes() {
        return Err(OpenDeliveryError::WrongNetwork);
    }
    if payload.inbox_pk != inbox_pk.serialize() {
        return Err(OpenDeliveryError::WrongRecipient);
    }

    let digest = payload_binding(payload);
    let signature = secp256k1::ecdsa::Signature::from_compact(&envelope.signature)
        .map_err(|_| OpenDeliveryError::BadSignature)?;
    Secp256k1::verification_only()
        .verify_ecdsa(&Message::from_digest(digest), &signature, council_pk)
        .map_err(|_| OpenDeliveryError::BadSignature)?;

    let sender_pk = PublicKey::from_slice(&payload.sender_eph_pk)
        .map_err(|_| OpenDeliveryError::DecryptFailed)?;
    let shared = SharedSecret::new(&sender_pk, inbox_sk);
    let aes_key = derive_aes_key(&shared, AesKeyDomain::CouncilKeyDelivery)
        .map_err(|_| OpenDeliveryError::DecryptFailed)?;

    if payload.encrypted_key.len() < AESGCM_NONCE_SIZE {
        return Err(OpenDeliveryError::DecryptFailed);
    }
    let (nonce_bytes, ciphertext) = payload.encrypted_key.split_at(AESGCM_NONCE_SIZE);
    let nonce: [u8; AESGCM_NONCE_SIZE] = nonce_bytes.try_into().expect("checked length above");
    let aad = payload_context_binding(payload);
    let mut plaintext = aes_decrypt_aead(&aes_key, ciphertext, nonce, &aad)
        .map_err(|_| OpenDeliveryError::DecryptFailed)?;

    let key: [u8; 32] = match plaintext.as_slice().try_into() {
        Ok(key) => key,
        Err(_) => {
            plaintext.zeroize();
            return Err(OpenDeliveryError::DecryptFailed);
        }
    };
    plaintext.zeroize();
    Ok(Zeroizing::new(key))
}

/// The one CBOR encoding of an envelope, used for persistence and for the
/// byte-identity redelivery check. ciborium encodes a fixed struct
/// deterministically, so equal envelopes always produce equal bytes.
pub fn canonical_envelope_bytes(envelope: &SignedDeliveryEnvelope) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(envelope, &mut bytes).context("encoding delivery envelope")?;
    Ok(bytes)
}

/// Inverse of [`canonical_envelope_bytes`], for loading persisted envelopes.
pub fn envelope_from_bytes(bytes: &[u8]) -> Result<SignedDeliveryEnvelope> {
    ciborium::from_reader(bytes).context("decoding delivery envelope")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn council() -> (SecretKey, PublicKey) {
        let sk = SecretKey::from_byte_array(&[0x77; 32]).unwrap();
        let pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk);
        (sk, pk)
    }

    fn inbox() -> (SecretKey, PublicKey) {
        let sk = SecretKey::from_byte_array(&[0x55; 32]).unwrap();
        let pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk);
        (sk, pk)
    }

    const NETWORK: [u8; 32] = [0x11; 32];
    const PURPOSE_KEY: [u8; 32] = [0x42; 32];

    fn sealed(epoch: u64) -> SignedDeliveryEnvelope {
        let (council_sk, _) = council();
        let (_, inbox_pk) = inbox();
        seal_delivery(
            &council_sk,
            &NetworkId::from_bytes(NETWORK),
            DeliveryPurpose::TxIo,
            epoch,
            &inbox_pk,
            &PURPOSE_KEY,
        )
        .unwrap()
    }

    #[test]
    fn seal_then_open_roundtrips() {
        let (_, council_pk) = council();
        let (inbox_sk, inbox_pk) = inbox();
        let envelope = sealed(1);
        let key = open_delivery(
            &envelope,
            &council_pk,
            &NetworkId::from_bytes(NETWORK),
            &inbox_sk,
            &inbox_pk,
        )
        .unwrap();
        assert_eq!(*key, PURPOSE_KEY);
    }

    #[test]
    fn open_rejects_wrong_network() {
        let (_, council_pk) = council();
        let (inbox_sk, inbox_pk) = inbox();
        let err = open_delivery(
            &sealed(1),
            &council_pk,
            &NetworkId::from_bytes([0x99; 32]),
            &inbox_sk,
            &inbox_pk,
        )
        .unwrap_err();
        assert_eq!(err, OpenDeliveryError::WrongNetwork);
    }

    #[test]
    fn open_rejects_wrong_recipient() {
        let (_, council_pk) = council();
        let other = EphemeralKeypair::generate();
        let err = open_delivery(
            &sealed(1),
            &council_pk,
            &NetworkId::from_bytes(NETWORK),
            &other.sk,
            &other.pk,
        )
        .unwrap_err();
        assert_eq!(err, OpenDeliveryError::WrongRecipient);
    }

    #[test]
    fn open_rejects_non_council_signer() {
        let (inbox_sk, inbox_pk) = inbox();
        let impostor = EphemeralKeypair::generate();
        let envelope = seal_delivery(
            &impostor.sk,
            &NetworkId::from_bytes(NETWORK),
            DeliveryPurpose::TxIo,
            1,
            &inbox_pk,
            &PURPOSE_KEY,
        )
        .unwrap();
        let (_, council_pk) = council();
        let err = open_delivery(
            &envelope,
            &council_pk,
            &NetworkId::from_bytes(NETWORK),
            &inbox_sk,
            &inbox_pk,
        )
        .unwrap_err();
        assert_eq!(err, OpenDeliveryError::BadSignature);
    }

    /// Tampering with any signed field after sealing breaks the signature —
    /// including swapping the ciphertext, which the binding's tail covers.
    #[test]
    fn open_rejects_tampered_fields() {
        let (_, council_pk) = council();
        let (inbox_sk, inbox_pk) = inbox();
        let network_id = NetworkId::from_bytes(NETWORK);

        let mut ciphertext_swap = sealed(1);
        ciphertext_swap.payload.encrypted_key = sealed(1).payload.encrypted_key;
        let mut epoch_bump = sealed(1);
        epoch_bump.payload.epoch = 2;
        let mut purpose_swap = sealed(1);
        purpose_swap.payload.purpose = DeliveryPurpose::Snapshot;
        let mut sender_swap = sealed(1);
        sender_swap.payload.sender_eph_pk = EphemeralKeypair::generate().pk.serialize();

        for (label, tampered) in [
            ("ciphertext swap", ciphertext_swap),
            ("epoch bump", epoch_bump),
            ("purpose swap", purpose_swap),
            ("sender swap", sender_swap),
        ] {
            let err = open_delivery(&tampered, &council_pk, &network_id, &inbox_sk, &inbox_pk)
                .unwrap_err();
            assert_eq!(err, OpenDeliveryError::BadSignature, "{label}");
        }
    }

    #[test]
    fn open_rejects_truncated_ciphertext_after_resign() {
        // A "council" that signs a garbage ciphertext: the signature is valid,
        // so the failure must surface as DecryptFailed, not a panic.
        let (council_sk, council_pk) = council();
        let (inbox_sk, inbox_pk) = inbox();
        let network_id = NetworkId::from_bytes(NETWORK);
        let mut envelope = sealed(1);
        envelope.payload.encrypted_key.truncate(8);
        let digest = payload_binding(&envelope.payload);
        envelope.signature = Secp256k1::signing_only()
            .sign_ecdsa(&Message::from_digest(digest), &council_sk)
            .serialize_compact();
        let err =
            open_delivery(&envelope, &council_pk, &network_id, &inbox_sk, &inbox_pk).unwrap_err();
        assert_eq!(err, OpenDeliveryError::DecryptFailed);
    }

    #[test]
    fn canonical_bytes_roundtrip_and_distinguish_envelopes() {
        let a = sealed(1);
        let bytes = canonical_envelope_bytes(&a).unwrap();
        assert_eq!(envelope_from_bytes(&bytes).unwrap(), a);
        // A fresh seal of the same key uses a fresh ephemeral + nonce, so the
        // canonical bytes differ — this is what makes EpochConflict detection
        // of non-identical redelivery meaningful.
        let b = sealed(1);
        assert_ne!(bytes, canonical_envelope_bytes(&b).unwrap());
    }
}
