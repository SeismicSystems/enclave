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
//!                                          verify q_b, appraise the requester's
//!                                          measurements (admission predicate),
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
//!
//! This module runs in the network-facing attestation service and owns only
//! the *evidence* side of the exchange: minting and verifying quotes over the
//! transcript bindings. Every key operation happens in the key custodian,
//! reached over its Unix socket: the requester's ephemeral secret never
//! leaves it (`CreateRootKeyBootstrapAttempt` retains it there), the
//! responder wraps there (`WrapRootKey`), and the requester unwraps and
//! installs there (`InstallRootKeyFromVerifiedBootstrapResponse`).

use anyhow::{Context, Result};
use rand::{TryRngCore as _, rngs::OsRng};
use secp256k1::PublicKey;
use seismic_attestation::{
    AdmissionPredicate, AttestationExchangeMessage, AttestationType, NetworkId,
    bindings::{binding64_from_digest32, root_key_request_binding, root_key_response_binding},
    generate_evidence, verify_evidence_with_predicate,
};
use seismic_custodian_ipc::CustodianClient;
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
    /// Requester ephemeral ECDH pubkey; the matching secret stays in the
    /// requester's custodian.
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
/// `requester_eph_pk` is the public half of the ephemeral key the local
/// custodian retained for this bootstrap attempt
/// (`CreateRootKeyBootstrapAttempt`); the matching secret never enters this
/// process.
pub fn build_root_key_request(
    network_id: &NetworkId,
    requester_eph_pk: &PublicKey,
    attestation_type: AttestationType,
) -> Result<RootKeyRequest> {
    let mut nonce_b = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut nonce_b)
        .expect("OS RNG must produce a handshake nonce");

    let binding = root_key_request_binding(network_id, &nonce_b, &requester_eph_pk.serialize());
    let evidence = generate_evidence(attestation_type, binding64_from_digest32(binding))
        .context("generating requester attestation evidence")?;

    Ok(RootKeyRequest {
        nonce_b,
        eph_pk_b: *requester_eph_pk,
        evidence,
    })
}

/// Responder step: verify the requester's evidence, have the custodian wrap
/// the root key for it, and attest the response.
///
/// The root key itself never appears here: only the custodian touches it, and
/// only to wrap it once the requester's evidence has verified. `admission` is
/// the responder's appraisal of the requester's verified measurements (the
/// requester must be running an admitted image — in production, registry
/// membership; see [`crate::admission`]). `network_id` is the responder's own
/// — verification recomputes the requester's binding from it, so a quote for a
/// different network fails the binding check.
pub async fn answer_root_key_request(
    request: &RootKeyRequest,
    network_id: &NetworkId,
    custodian: &mut CustodianClient,
    admission: &impl AdmissionPredicate,
    attestation_type: AttestationType,
) -> Result<RootKeyResponse> {
    // 1. Verify the requester's quote and appraise its measurements,
    //    recomputing the expected binding from *our* network_id + the
    //    request's claimed fields.
    let expected =
        root_key_request_binding(network_id, &request.nonce_b, &request.eph_pk_b.serialize());
    verify_evidence_with_predicate(
        request.evidence.clone(),
        binding64_from_digest32(expected),
        admission,
    )
    .await
    .context("verifying requester attestation evidence")?;

    // 2. Verification succeeded: authorize the custodian to wrap the root key
    //    to the requester's attested ephemeral key, with the verified request
    //    binding as the AEAD AAD. Calling `WrapRootKey` *is* the authorization
    //    assertion — the custodian's ACL confines it to this service.
    let wrap = custodian
        .wrap_root_key(expected, request.eph_pk_b.serialize())
        .await
        .context("wrapping root key for peer")?;
    let eph_pk_a = PublicKey::from_slice(&wrap.responder_eph_pk)
        .context("custodian returned an invalid responder ephemeral key")?;

    // 3. Attest over the response transcript, committing to the ciphertext.
    let binding = root_key_response_binding(
        network_id,
        &request.nonce_b,
        &wrap.responder_eph_pk,
        &wrap.wrapped,
    );
    let evidence = generate_evidence(attestation_type, binding64_from_digest32(binding))
        .context("generating responder attestation evidence")?;

    Ok(RootKeyResponse {
        eph_pk_a,
        wrapped: wrap.wrapped,
        evidence,
    })
}

/// Requester step 2: verify the responder's evidence over the response
/// transcript.
///
/// `request` is the matching request (we re-derive bindings from it rather
/// than trusting the response to echo them). `admission` is the requester's
/// appraisal of the responder's verified measurements. Returns the
/// request-transcript binding, recomputed from our own copies of the request
/// fields — the AEAD AAD the custodian needs to open the wrapped key on
/// install. The wrapped key stays sealed through this function: only the
/// custodian, holding the attempt's ephemeral secret, can open it.
pub async fn verify_root_key_response(
    response: &RootKeyResponse,
    request: &RootKeyRequest,
    network_id: &NetworkId,
    admission: &impl AdmissionPredicate,
) -> Result<[u8; 32]> {
    // Verify the responder's quote: recompute the response binding from our
    // own network_id + the nonce we chose + the responder's ephemeral key +
    // the exact ciphertext. A tampered field or a foreign network fails here.
    let expected = root_key_response_binding(
        network_id,
        &request.nonce_b,
        &response.eph_pk_a.serialize(),
        &response.wrapped,
    );
    verify_evidence_with_predicate(
        response.evidence.clone(),
        binding64_from_digest32(expected),
        admission,
    )
    .await
    .context("verifying responder attestation evidence")?;

    Ok(root_key_request_binding(
        network_id,
        &request.nonce_b,
        &request.eph_pk_b.serialize(),
    ))
}
