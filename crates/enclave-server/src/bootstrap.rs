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
//! The root key itself only ever crosses the wire AEAD-wrapped under the
//! ECDH-derived key; the AEAD tag plus the responder quote let the requester
//! reject anything not produced by a genuine peer enclave for this request.

use anyhow::{Context, Result};
use rand::{TryRngCore as _, rngs::OsRng};
use secp256k1::{PublicKey, SecretKey};
use seismic_attestation::{
    AttestationExchangeMessage, AttestationType, NetworkId, SeismicMeasurementPolicy,
    bindings::{binding64_from_digest32, root_key_request_binding, root_key_response_binding},
    generate_evidence, verify_evidence,
};
use seismic_key_custodian::{
    Custodian, EphemeralKeypair, VerifiedPeerAuthorization, unwrap_root_key,
};
use serde::{Deserialize, Serialize};

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
    /// `nonce(12) || AES-256-GCM(root_key)`; see
    /// [`Custodian::wrap_root_key_for_peer`].
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

/// Responder step: verify the requester's evidence, have the custodian wrap
/// the root key for it, and attest the response.
///
/// The root key itself never appears here: only the custodian touches it, and
/// only to wrap it once the requester's evidence has verified. `policy` is the
/// responder's measurement allowlist (the requester must be running an
/// admitted image). `network_id` is the responder's own — verification
/// recomputes the requester's binding from it, so a quote for a different
/// network fails the binding check.
pub async fn answer_root_key_request(
    request: &RootKeyRequest,
    network_id: &NetworkId,
    custodian: &Custodian,
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

    // 2. Verification succeeded: authorize the custodian to wrap the root key
    //    to the requester's attested ephemeral key, with the verified request
    //    binding as the AEAD AAD.
    let auth = VerifiedPeerAuthorization {
        root_key_request_binding: expected,
    };
    let wrap = custodian
        .wrap_root_key_for_peer(&auth, &request.eph_pk_b)
        .context("wrapping root key for peer")?;

    // 3. Attest over the response transcript, committing to the ciphertext.
    let binding = root_key_response_binding(
        network_id,
        &request.nonce_b,
        &wrap.responder_eph_pk.serialize(),
        &wrap.wrapped,
    );
    let evidence = generate_evidence(attestation_type, binding64_from_digest32(binding))
        .context("generating responder attestation evidence")?;

    Ok(RootKeyResponse {
        eph_pk_a: wrap.responder_eph_pk,
        wrapped: wrap.wrapped,
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

    // 2. ECDH to the responder's ephemeral key, then AEAD-open, with the
    //    request-binding AAD recomputed from our own copies of the fields.
    let request_binding =
        root_key_request_binding(network_id, &request.nonce_b, &request.eph_pk_b.serialize());
    unwrap_root_key(
        eph_sk_b,
        &response.eph_pk_a,
        &response.wrapped,
        &request_binding,
    )
}
