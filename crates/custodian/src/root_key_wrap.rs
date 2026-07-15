//! Wrapping `root_key` to an authorized peer's ephemeral ECDH key.
//!
//! This is the custody half of the root-key bootstrap handshake: the caller
//! (the attestation service) runs the attested protocol — verifying
//! the requester's quote and minting the responder's — while this module only
//! turns "authorized peer + its ephemeral key" into an AEAD-wrapped root key.
//! The transcript digest the caller verified rides along as the AEAD AAD, so
//! a wrapped key cannot be lifted onto a different handshake.

use crate::custodian::Custodian;
use anyhow::{Context, Result, anyhow};
use rand::{TryRngCore as _, rngs::OsRng};
use secp256k1::{PublicKey, Secp256k1, SecretKey, ecdh::SharedSecret};
use seismic_crypto::{
    AESGCM_NONCE_SIZE, AesKeyDomain, Nonce, aes_decrypt_aead, aes_encrypt_aead, derive_aes_key,
};

/// A freshly minted ephemeral secp256k1 ECDH keypair for one handshake.
///
/// Held only for the lifetime of a single exchange and dropped after; never
/// derived from or mixed with the root key, so a leak reveals nothing about it.
pub struct EphemeralKeypair {
    pub sk: SecretKey,
    pub pk: PublicKey,
}

impl EphemeralKeypair {
    /// Draw the scalar from the OS CSPRNG (like [`Custodian::new_as_genesis`]),
    /// retrying on the negligible chance of an out-of-range scalar. We seed from
    /// bytes rather than secp256k1's own `generate_keypair` because that helper
    /// wants a `rand` 0.8 RNG, while this workspace is on `rand` 0.9.
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

    /// Compressed 33-byte SEC1 encoding, the form the binding helpers hash.
    pub fn pk_compressed(&self) -> [u8; 33] {
        self.pk.serialize()
    }
}

/// Attestation-verified permission to release `root_key` to one peer.
///
/// Constructing one asserts that the peer's evidence for exactly this
/// handshake transcript has been verified against admission policy. The
/// custodian trusts it blindly — by design it cannot re-check — so build one
/// only at the point where verification just succeeded. Who verifies, and
/// against what policy, is the caller's affair; that is what keeps this crate
/// free of the attestation stack.
pub struct VerifiedPeerAuthorization {
    /// Digest of the verified request transcript (network id, request nonce,
    /// peer ephemeral key), as defined by
    /// `seismic_attestation::bindings::root_key_request_binding`. The wire
    /// protocol pins that choice: the digest becomes the AEAD AAD, and the
    /// requester independently recomputes it to unwrap, tying the wrapped
    /// root key to the transcript that was actually verified. The custodian
    /// never computes or checks the digest — it carries opaque bytes into the
    /// AAD, which is what keeps this crate free of the attestation stack.
    pub root_key_request_binding: [u8; 32],
}

/// One wrap operation's output: the wrapped root key plus the custodian-side
/// ephemeral pubkey the peer needs for ECDH. The matching ephemeral secret
/// never leaves the custodian.
pub struct WrappedRootKey {
    /// Custodian-side ephemeral ECDH pubkey for this handshake.
    pub responder_eph_pk: PublicKey,
    /// `nonce(12) || AES-256-GCM ciphertext+tag` over `root_key`.
    pub wrapped: Vec<u8>,
}

impl Custodian {
    /// AEAD-wrap `root_key` for an authorized peer's ephemeral ECDH key.
    ///
    /// Output layout: `nonce(12 bytes) || AES-256-GCM ciphertext+tag`, with
    /// the authorization's request-transcript digest as AAD — the wrapped
    /// blob can't be replayed onto a different handshake even before the peer
    /// checks the responder's quote.
    pub fn wrap_root_key_for_peer(
        &self,
        auth: &VerifiedPeerAuthorization,
        peer_eph_pk: &PublicKey,
    ) -> Result<WrappedRootKey> {
        let eph = EphemeralKeypair::generate();
        let aes_key = derive_handshake_key(&eph.sk, peer_eph_pk)?;

        let nonce = Nonce::new_rand();
        let ciphertext = aes_encrypt_aead(
            &aes_key,
            self.root_key.as_ref(),
            nonce.clone(),
            &auth.root_key_request_binding,
        )
        .context("AEAD-wrapping root key")?;

        let mut wrapped = Vec::with_capacity(AESGCM_NONCE_SIZE + ciphertext.len());
        wrapped.extend_from_slice(&nonce.0);
        wrapped.extend_from_slice(&ciphertext);
        Ok(WrappedRootKey {
            responder_eph_pk: eph.pk,
            wrapped,
        })
    }
}

/// Inverse of [`Custodian::wrap_root_key_for_peer`], run by the requester side
/// of the handshake once it has verified the responder's evidence: ECDH the
/// requester's ephemeral secret against the responder's ephemeral pubkey, then
/// AEAD-open with the request-binding AAD recomputed from the requester's own
/// copies of the transcript fields.
pub fn unwrap_root_key(
    eph_sk: &SecretKey,
    responder_eph_pk: &PublicKey,
    wrapped: &[u8],
    root_key_request_binding: &[u8; 32],
) -> Result<[u8; 32]> {
    if wrapped.len() < AESGCM_NONCE_SIZE {
        return Err(anyhow!("wrapped root key too short to contain a nonce"));
    }
    let (nonce_bytes, ciphertext) = wrapped.split_at(AESGCM_NONCE_SIZE);
    let nonce: [u8; AESGCM_NONCE_SIZE] = nonce_bytes.try_into().expect("checked length above");

    let aes_key = derive_handshake_key(eph_sk, responder_eph_pk)?;
    let plaintext = aes_decrypt_aead(&aes_key, ciphertext, nonce, root_key_request_binding)
        .context("opening wrapped root key (AEAD tag mismatch)")?;
    plaintext
        .try_into()
        .map_err(|_| anyhow!("unwrapped root key is not 32 bytes"))
}

/// Derive the symmetric handshake key from an ECDH shared secret.
///
/// Uses [`AesKeyDomain::RootKeyWrap`], the handshake's own domain-separation
/// label: a key derived here is unusable in any other protocol context, and
/// vice versa. Both custodian sides must run the same release.
fn derive_handshake_key(
    sk: &SecretKey,
    pk: &PublicKey,
) -> Result<aes_gcm::Key<aes_gcm::Aes256Gcm>> {
    let shared = SharedSecret::new(pk, sk);
    derive_aes_key(&shared, AesKeyDomain::RootKeyWrap)
        .map_err(|e| anyhow!("deriving handshake AES key: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // End-to-end wrap/unwrap with matching transcripts recovers the key; this
    // exercises the ECDH + AEAD path without needing real attestation evidence.
    #[test]
    fn wrap_then_unwrap_roundtrips() {
        let root_key = [0x42u8; 32];
        let custodian = Custodian::new(root_key);
        let auth = VerifiedPeerAuthorization {
            root_key_request_binding: [0x33; 32],
        };

        let requester = EphemeralKeypair::generate();
        let response = custodian
            .wrap_root_key_for_peer(&auth, &requester.pk)
            .unwrap();

        let recovered = unwrap_root_key(
            &requester.sk,
            &response.responder_eph_pk,
            &response.wrapped,
            &auth.root_key_request_binding,
        )
        .unwrap();
        assert_eq!(recovered, root_key);
    }

    // The wrapped key is bound to the verified transcript via the AEAD AAD:
    // open it under any other binding digest (a different nonce, network, or
    // ephemeral key upstream) and the tag check must fail.
    #[test]
    fn unwrap_rejects_foreign_request_binding() {
        let root_key = [0x42u8; 32];
        let custodian = Custodian::new(root_key);
        let auth = VerifiedPeerAuthorization {
            root_key_request_binding: [0x33; 32],
        };

        let requester = EphemeralKeypair::generate();
        let response = custodian
            .wrap_root_key_for_peer(&auth, &requester.pk)
            .unwrap();

        let err = unwrap_root_key(
            &requester.sk,
            &response.responder_eph_pk,
            &response.wrapped,
            &[0xFF; 32],
        )
        .unwrap_err();
        assert!(err.to_string().contains("AEAD tag mismatch"));
    }
}
