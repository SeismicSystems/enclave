//! The encrypted root-key bootstrap.
//!
//! A booting non-genesis node (the *requester*, side `b` in the binding
//! helpers) needs the network root key. A node that already holds it (the
//! *responder*, side `a`) returns it AEAD-wrapped to the requester's attested
//! ephemeral key.
//! The exchange is a one-round handshake, both halves attested and bound to the
//! same `network_id = H(network-manifest.json)`:
//!
//! ```text
//!   requester                                            responder
//!   ---------                                            ---------
//!   eph (sk_b, pk_b); nonce_b
//!   q_b = quote over root_key_request_binding(
//!             network_id, nonce_b, eph_pk_b)
//!   ----  RootKeyRequest { nonce_b, eph_pk_b, q_b } --->
//!                                          verify q_b against requester policy,
//!                                          recompute its binding from our own
//!                                          network_id + the request fields
//!                                          eph (sk_a, pk_a)
//!                                          wrapped = AEAD_ECDH(eph_sk_a, eph_pk_b,
//!                                                    root_key; aad = request binding)
//!                                          q_a = quote over root_key_response_binding(
//!                                                    network_id, nonce_b, eph_pk_a, wrapped)
//!   <---  RootKeyResponse { eph_pk_a, wrapped, q_a }  ----
//!   verify q_a; recompute response binding from
//!   our network_id + nonce_b + eph_pk_a + wrapped;
//!   ECDH(eph_sk_b, eph_pk_a) -> unwrap root_key
//! ```
//!
//! Why each field is in the transcript:
//! - `network_id` — both sides verify the peer's binding against *their own*
//!   id, so a quote minted on a clone network can't satisfy this one.
//! - `nonce_b` — requester-fresh; ties the responder's quote to this exact
//!   request so a captured response can't be replayed.
//! - `eph_pk_b` / `eph_pk_a` — bind the ECDH inputs into the attested
//!   transcript, so a MITM can't substitute its own ephemeral key and learn the
//!   wrapped key.
//! - `wrapped` (in the response binding) and the request binding (as AEAD AAD)
//!   — bind the ciphertext to the handshake it belongs to.
//!
//! The root key itself only ever crosses the wire AEAD-sealed under the
//! ECDH-derived key; the AEAD tag plus the responder quote let the requester
//! reject anything not produced by a genuine peer enclave for this request.

use anyhow::{Context, Result, anyhow};
use rand::{TryRngCore as _, rngs::OsRng};
use seismic_attestation::{
    AttestationExchangeMessage, AttestationType, NetworkId, SeismicMeasurementPolicy,
    bindings::{binding64_from_digest32, root_key_request_binding, root_key_response_binding},
    generate_evidence, verify_evidence,
};
use seismic_enclave::{
    AESGCM_NONCE_SIZE, Nonce, aes_decrypt_aead, aes_encrypt_aead, derive_aes_key,
    secp256k1::{PublicKey, Secp256k1, SecretKey, ecdh::SharedSecret},
};
use serde::{Deserialize, Serialize};

/// A freshly minted ephemeral secp256k1 ECDH keypair for one handshake.
///
/// Held only for the lifetime of a single exchange and dropped after; never
/// derived from or mixed with the root key, so a leak reveals nothing about it.
struct EphemeralKeypair {
    sk: SecretKey,
    pk: PublicKey,
}

impl EphemeralKeypair {
    /// Draw the scalar from the OS CSPRNG (like `KeyManager::new_as_genesis`),
    /// retrying on the negligible chance of an out-of-range scalar. We seed from
    /// bytes rather than secp256k1's own `generate_keypair` because that helper
    /// wants a `rand` 0.8 RNG, while this workspace is on `rand` 0.9.
    fn generate() -> Self {
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
    fn pk_compressed(&self) -> [u8; 33] {
        self.pk.serialize()
    }
}

/// The requester's half of the handshake: a fresh nonce + ephemeral pubkey,
/// attested by `evidence` over [`root_key_request_binding`].
///
/// The ephemeral key travels as a `secp256k1::PublicKey` (compressed on the
/// wire); the binding helpers consume its 33-byte SEC1 form via `.serialize()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootKeyRequest {
    /// Requester-fresh replay protection, bound into both quotes.
    pub nonce_b: [u8; 32],
    /// Requester ephemeral ECDH pubkey.
    pub eph_pk_b: PublicKey,
    /// Requester attestation over `root_key_request_binding(network_id,
    /// nonce_b, eph_pk_b)`.
    pub evidence: AttestationExchangeMessage,
}

/// The responder's half: its ephemeral pubkey, the AEAD-wrapped root key, and
/// its attestation over [`root_key_response_binding`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootKeyResponse {
    /// Responder ephemeral ECDH pubkey.
    pub eph_pk_a: PublicKey,
    /// `nonce(12) || AES-256-GCM(root_key)`; see [`wrap_root_key_for_peer`].
    pub wrapped: Vec<u8>,
    /// Responder attestation over `root_key_response_binding(network_id,
    /// nonce_b, eph_pk_a, wrapped)`.
    pub evidence: AttestationExchangeMessage,
}

/// Requester step 1: build the request the booting node POSTs to a peer.
///
/// Returns the wire request plus the ephemeral secret the caller must keep to
/// unwrap the response (see [`unwrap_root_key_from_response`]).
pub fn build_root_key_request(
    network_id: &NetworkId,
    attestation_type: AttestationType,
) -> Result<(RootKeyRequest, SecretKey)> {
    let eph = EphemeralKeypair::generate();

    let mut nonce_b = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut nonce_b)
        .expect("OS RNG must produce a handshake nonce");

    let binding = root_key_request_binding(network_id, &nonce_b, &eph.pk_compressed());
    let evidence = generate_evidence(attestation_type, binding64_from_digest32(binding))
        .context("generating requester attestation evidence")?;

    let request = RootKeyRequest {
        nonce_b,
        eph_pk_b: eph.pk,
        evidence,
    };
    Ok((request, eph.sk))
}

/// Responder step: verify the requester's evidence, then return the root key
/// AEAD-wrapped under a fresh ECDH key and the responder's own attestation.
///
/// `root_key` is consumed only to seal it; it never leaves this function in the
/// clear. `policy` is the responder's measurement allowlist (the requester must
/// be running an admitted image). `network_id` is the responder's own —
/// verification recomputes the requester's binding from it, so a quote for a
/// different network fails the binding check.
pub async fn answer_root_key_request(
    request: &RootKeyRequest,
    network_id: &NetworkId,
    root_key: &[u8; 32],
    policy: SeismicMeasurementPolicy,
    attestation_type: AttestationType,
) -> Result<RootKeyResponse> {
    // 1. Verify the requester's quote against our policy, recomputing the
    //    expected binding from *our* network_id + the request's claimed fields.
    let expected =
        root_key_request_binding(network_id, &request.nonce_b, &request.eph_pk_b.serialize());
    verify_evidence(
        request.evidence.clone(),
        binding64_from_digest32(expected),
        policy,
    )
    .await
    .context("verifying requester attestation evidence")?;

    // 2. Wrap the root key for the requester's attested ephemeral key.
    let eph_a = EphemeralKeypair::generate();
    let wrapped =
        wrap_root_key_for_peer(&eph_a.sk, &request.eph_pk_b, root_key, network_id, request)?;

    // 3. Attest over the response transcript, committing to the ciphertext.
    let binding = root_key_response_binding(
        network_id,
        &request.nonce_b,
        &eph_a.pk_compressed(),
        &wrapped,
    );
    let evidence = generate_evidence(attestation_type, binding64_from_digest32(binding))
        .context("generating responder attestation evidence")?;

    Ok(RootKeyResponse {
        eph_pk_a: eph_a.pk,
        wrapped,
        evidence,
    })
}

/// Requester step 2: verify the responder's evidence and unwrap the root key.
///
/// `eph_sk_b` is the secret returned by [`build_root_key_request`]; `request`
/// is the matching request (we re-derive bindings from it rather than trusting
/// the response to echo them). `policy` is the requester's allowlist for the
/// responder. The wrapped root key is opened only after the responder quote
/// verifies and the AEAD tag validates under the requester's ephemeral key.
pub async fn unwrap_root_key_from_response(
    response: &RootKeyResponse,
    request: &RootKeyRequest,
    eph_sk_b: &SecretKey,
    network_id: &NetworkId,
    policy: SeismicMeasurementPolicy,
) -> Result<[u8; 32]> {
    // 1. Verify the responder's quote: recompute the response binding from our
    //    own network_id + the nonce we chose + the responder's ephemeral key +
    //    the exact ciphertext. A tampered field or a foreign network fails here.
    let expected = root_key_response_binding(
        network_id,
        &request.nonce_b,
        &response.eph_pk_a.serialize(),
        &response.wrapped,
    );
    verify_evidence(
        response.evidence.clone(),
        binding64_from_digest32(expected),
        policy,
    )
    .await
    .context("verifying responder attestation evidence")?;

    // 2. ECDH to the responder's ephemeral key, then AEAD-open.
    unwrap_root_key(
        eph_sk_b,
        &response.eph_pk_a,
        &response.wrapped,
        network_id,
        request,
    )
}

/// AEAD-seal `root_key` for a peer's ephemeral ECDH key.
///
/// Output layout: `nonce(12 bytes) || AES-256-GCM ciphertext+tag`. The AEAD AAD
/// is the [`root_key_request_binding`] digest, so the sealed key is
/// cryptographically tied to this exact request transcript (network_id,
/// nonce_b, eph_pk_b) — a wrapped blob can't be lifted onto a different
/// handshake even before the responder quote is checked.
fn wrap_root_key_for_peer(
    eph_sk_a: &SecretKey,
    eph_pk_b: &PublicKey,
    root_key: &[u8; 32],
    network_id: &NetworkId,
    request: &RootKeyRequest,
) -> Result<Vec<u8>> {
    let aes_key = derive_handshake_key(eph_sk_a, eph_pk_b)?;
    let aad = root_key_request_binding(network_id, &request.nonce_b, &request.eph_pk_b.serialize());

    let nonce = Nonce::new_rand();
    let ciphertext = aes_encrypt_aead(&aes_key, root_key, nonce.clone(), &aad)
        .context("sealing root key for peer")?;

    let mut wrapped = Vec::with_capacity(AESGCM_NONCE_SIZE + ciphertext.len());
    wrapped.extend_from_slice(&nonce.0);
    wrapped.extend_from_slice(&ciphertext);
    Ok(wrapped)
}

/// Inverse of [`wrap_root_key_for_peer`]: ECDH + AEAD-open, with the same
/// request-binding AAD recomputed from the requester's own copies.
fn unwrap_root_key(
    eph_sk_b: &SecretKey,
    eph_pk_a: &PublicKey,
    wrapped: &[u8],
    network_id: &NetworkId,
    request: &RootKeyRequest,
) -> Result<[u8; 32]> {
    if wrapped.len() < AESGCM_NONCE_SIZE {
        return Err(anyhow!("wrapped root key too short to contain a nonce"));
    }
    let (nonce_bytes, ciphertext) = wrapped.split_at(AESGCM_NONCE_SIZE);
    let nonce: [u8; AESGCM_NONCE_SIZE] = nonce_bytes.try_into().expect("checked length above");

    let aes_key = derive_handshake_key(eph_sk_b, eph_pk_a)?;
    let aad = root_key_request_binding(network_id, &request.nonce_b, &request.eph_pk_b.serialize());

    let plaintext = aes_decrypt_aead(&aes_key, ciphertext, nonce, &aad)
        .context("opening wrapped root key (AEAD tag mismatch)")?;
    plaintext
        .try_into()
        .map_err(|_| anyhow!("unwrapped root key is not 32 bytes"))
}

/// Derive the symmetric handshake key from an ECDH shared secret.
///
/// Reuses [`derive_aes_key`] so wrap and unwrap stay in lockstep with the rest
/// of the enclave's ECDH-AES key schedule.
fn derive_handshake_key(
    sk: &SecretKey,
    pk: &PublicKey,
) -> Result<aes_gcm::Key<aes_gcm::Aes256Gcm>> {
    let shared = SharedSecret::new(pk, sk);
    derive_aes_key(&shared).map_err(|e| anyhow!("deriving handshake AES key: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // End-to-end wrap/unwrap with matching transcripts recovers the key; this
    // exercises the ECDH + AEAD path without needing real attestation evidence.
    #[test]
    fn wrap_then_unwrap_roundtrips() {
        let network_id = NetworkId::from_bytes([0x11; 32]);
        let root_key = [0x42u8; 32];

        let requester = EphemeralKeypair::generate();
        let request = RootKeyRequest {
            nonce_b: [0x33; 32],
            eph_pk_b: requester.pk,
            evidence: AttestationExchangeMessage::without_attestation(),
        };

        let responder = EphemeralKeypair::generate();
        let wrapped = wrap_root_key_for_peer(
            &responder.sk,
            &requester.pk,
            &root_key,
            &network_id,
            &request,
        )
        .unwrap();

        let recovered = unwrap_root_key(
            &requester.sk,
            &responder.pk,
            &wrapped,
            &network_id,
            &request,
        )
        .unwrap();
        assert_eq!(recovered, root_key);
    }

    // A wrapped blob is bound to its request transcript via the AEAD AAD: open
    // it under a different nonce_b and the tag check must fail.
    #[test]
    fn unwrap_rejects_foreign_request_binding() {
        let network_id = NetworkId::from_bytes([0x11; 32]);
        let root_key = [0x42u8; 32];

        let requester = EphemeralKeypair::generate();
        let request = RootKeyRequest {
            nonce_b: [0x33; 32],
            eph_pk_b: requester.pk,
            evidence: AttestationExchangeMessage::without_attestation(),
        };
        let responder = EphemeralKeypair::generate();
        let wrapped = wrap_root_key_for_peer(
            &responder.sk,
            &requester.pk,
            &root_key,
            &network_id,
            &request,
        )
        .unwrap();

        let mut tampered = request.clone();
        tampered.nonce_b = [0xFF; 32];
        let err = unwrap_root_key(
            &requester.sk,
            &responder.pk,
            &wrapped,
            &network_id,
            &tampered,
        )
        .unwrap_err();
        assert!(err.to_string().contains("AEAD tag mismatch"));
    }

    // Wrong network_id changes the AAD just like a wrong nonce does.
    #[test]
    fn unwrap_rejects_foreign_network() {
        let net_a = NetworkId::from_bytes([0x11; 32]);
        let net_b = NetworkId::from_bytes([0x22; 32]);
        let root_key = [0x42u8; 32];

        let requester = EphemeralKeypair::generate();
        let request = RootKeyRequest {
            nonce_b: [0x33; 32],
            eph_pk_b: requester.pk,
            evidence: AttestationExchangeMessage::without_attestation(),
        };
        let responder = EphemeralKeypair::generate();
        let wrapped =
            wrap_root_key_for_peer(&responder.sk, &requester.pk, &root_key, &net_a, &request)
                .unwrap();

        assert!(unwrap_root_key(&requester.sk, &responder.pk, &wrapped, &net_b, &request).is_err());
    }
}
