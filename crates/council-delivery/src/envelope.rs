//! Sealing and opening council delivery envelopes.
//!
//! A sealed envelope is independently authenticated and confidential: the
//! council's Ethereum-wallet signature (65-byte recoverable ECDSA over the
//! EIP-712 digest in [`crate::eip712`]) covers the full payload including
//! the ciphertext, and the 32-byte purpose key is AEAD-encrypted to the
//! custodian's inbox key with the context digest as AAD. Verification never
//! requires the plaintext, so envelopes persist verbatim and are re-verified
//! on every load.
//!
//! [`seal_delivery`] signs with a locally held key (tests, script-driven
//! councils). A wallet-driven council instead encrypts via the same path,
//! has the wallet sign [`crate::eip712::typed_data_json`], and attaches the
//! wallet's signature to the payload — the digest is identical.
//!
//! [`open_delivery`] is pure per-envelope validation; epoch sequencing and
//! conflict rules live with the caller's state, not here.

use crate::bindings::payload_context_binding;
use crate::eip712::{address_from_pubkey, payload_digest};
use crate::messages::{DeliveryPurpose, SignedDeliveryEnvelope};
use anyhow::{Context as _, Result, anyhow};
use rand::{TryRngCore as _, rngs::OsRng};
use secp256k1::ecdh::SharedSecret;
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
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

    let signature = sign_payload(council_sk, &payload);
    Ok(SignedDeliveryEnvelope { payload, signature })
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

/// Why an envelope failed to open. Sanitized-by-construction: variants carry
/// no payload detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OpenDeliveryError {
    #[error("delivery is for a different network")]
    WrongNetwork,
    #[error("delivery is sealed to a different inbox key")]
    WrongRecipient,
    #[error("delivery signature does not recover to the council address")]
    BadSignature,
    #[error("delivery ciphertext failed to open")]
    DecryptFailed,
}

/// Verify one envelope against the council address and this custodian's
/// identity, then decrypt the purpose key. Checks recipient and network
/// before the signature so responses distinguish misdirection from forgery.
pub fn open_delivery(
    envelope: &SignedDeliveryEnvelope,
    council_address: &[u8; 20],
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

    let signer = recover_signer(envelope).ok_or(OpenDeliveryError::BadSignature)?;
    if &signer != council_address {
        return Err(OpenDeliveryError::BadSignature);
    }

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

    fn council() -> (SecretKey, [u8; 20]) {
        let sk = SecretKey::from_byte_array(&[0x77; 32]).unwrap();
        let pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk);
        (sk, address_from_pubkey(&pk))
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
        let (_, council_address) = council();
        let (inbox_sk, inbox_pk) = inbox();
        let envelope = sealed(1);
        let key = open_delivery(
            &envelope,
            &council_address,
            &NetworkId::from_bytes(NETWORK),
            &inbox_sk,
            &inbox_pk,
        )
        .unwrap();
        assert_eq!(*key, PURPOSE_KEY);
    }

    #[test]
    fn open_rejects_wrong_network() {
        let (_, council_address) = council();
        let (inbox_sk, inbox_pk) = inbox();
        let err = open_delivery(
            &sealed(1),
            &council_address,
            &NetworkId::from_bytes([0x99; 32]),
            &inbox_sk,
            &inbox_pk,
        )
        .unwrap_err();
        assert_eq!(err, OpenDeliveryError::WrongNetwork);
    }

    #[test]
    fn open_rejects_wrong_recipient() {
        let (_, council_address) = council();
        let other = EphemeralKeypair::generate();
        let err = open_delivery(
            &sealed(1),
            &council_address,
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
        let (_, council_address) = council();
        let err = open_delivery(
            &envelope,
            &council_address,
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
        let (_, council_address) = council();
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
            let err = open_delivery(
                &tampered,
                &council_address,
                &network_id,
                &inbox_sk,
                &inbox_pk,
            )
            .unwrap_err();
            assert_eq!(err, OpenDeliveryError::BadSignature, "{label}");
        }
    }

    #[test]
    fn open_rejects_truncated_ciphertext_after_resign() {
        // A "council" that signs a garbage ciphertext: the signature is valid,
        // so the failure must surface as DecryptFailed, not a panic.
        let (council_sk, council_address) = council();
        let (inbox_sk, inbox_pk) = inbox();
        let network_id = NetworkId::from_bytes(NETWORK);
        let mut envelope = sealed(1);
        envelope.payload.encrypted_key.truncate(8);
        envelope.signature = sign_payload(&council_sk, &envelope.payload);
        let err = open_delivery(
            &envelope,
            &council_address,
            &network_id,
            &inbox_sk,
            &inbox_pk,
        )
        .unwrap_err();
        assert_eq!(err, OpenDeliveryError::DecryptFailed);
    }

    /// End-to-end Ethereum-wallet compatibility: this signature was produced
    /// by foundry (`cast wallet sign --data '<typed_data_json(payload)>'`
    /// with private key 0x77..77, address
    /// 0xAe72A48c1a36bd18Af168541c53037965d26e4A8), not by this crate. It
    /// must recover to the council address — pinning that a stock wallet
    /// signing [`crate::eip712::typed_data_json`] yields an envelope this
    /// code accepts.
    #[test]
    fn wallet_produced_signature_recovers_to_the_council_address() {
        let payload = DeliveryPayload {
            network_id: [0x11; 32],
            purpose: DeliveryPurpose::TxIo,
            epoch: 7,
            sender_eph_pk: [0x22; 33],
            inbox_pk: [0x33; 33],
            encrypted_key: vec![0x44; 60],
        };
        let cast_signature = hex::decode(
            "b681ef563a3901fb7f7b6e946416cfc0f6b4764c8b697ee4a975a83d7d70bdca\
             53636f06e0dd2057558716397bc00ad7e371c6659fe81aadf1158b78878272621b",
        )
        .unwrap();
        let envelope = SignedDeliveryEnvelope {
            payload,
            signature: cast_signature.try_into().unwrap(),
        };
        let (_, council_address) = council();
        assert_eq!(
            hex::encode(council_address),
            "ae72a48c1a36bd18af168541c53037965d26e4a8"
        );
        assert_eq!(recover_signer(&envelope), Some(council_address));
        // And our locally signed envelopes recover identically.
        let locally_signed = SignedDeliveryEnvelope {
            signature: sign_payload(&council().0, &envelope.payload),
            payload: envelope.payload,
        };
        assert_eq!(recover_signer(&locally_signed), Some(council_address));
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
