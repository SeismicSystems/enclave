//! The signed payload for observer fetches.
//!
//! An observer custodian authenticates to its parent by signing with an
//! ed25519 child key derived from the parent's own master node key (the
//! derivation lives in `seismic-observer-key`; this module only defines what
//! the child key signs). The payload binds a domain tag, a connection-local
//! single-use nonce handed out by the parent (`CouncilResponse::Challenge`),
//! and the canonical CBOR of the request — fixed-length fields before the
//! variable tail, the repo's binding layout rule. The nonce is what makes a
//! captured signature worthless to replay; the request's `network_id` scopes
//! it to one deployment.

use crate::messages::ObserverFetchRequest;
use anyhow::{Context as _, Result};

/// Domain for [`observer_fetch_signing_payload`].
pub const OBSERVER_FETCH_DOMAIN: &[u8] = b"seismic-observer-fetch-v1:";

/// What the observer's child key signs:
/// `DOMAIN || nonce(32) || canonical CBOR(request)`.
///
/// ciborium encodes a fixed struct deterministically (the same property
/// `canonical_envelope_bytes` relies on), so signer and verifier always
/// reconstruct identical bytes.
pub fn observer_fetch_signing_payload(
    nonce: &[u8; 32],
    request: &ObserverFetchRequest,
) -> Result<Vec<u8>> {
    let mut payload = Vec::with_capacity(OBSERVER_FETCH_DOMAIN.len() + 32 + 128);
    payload.extend_from_slice(OBSERVER_FETCH_DOMAIN);
    payload.extend_from_slice(nonce);
    ciborium::into_writer(request, &mut payload).context("encoding observer fetch request")?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::ObserverQuery;

    fn request() -> ObserverFetchRequest {
        ObserverFetchRequest {
            network_id: [0x11; 32],
            observer_index: 3,
            query: ObserverQuery::Envelopes { from_epoch: 5 },
        }
    }

    #[test]
    fn payload_is_deterministic() {
        let nonce = [0xAB; 32];
        assert_eq!(
            observer_fetch_signing_payload(&nonce, &request()).unwrap(),
            observer_fetch_signing_payload(&nonce, &request()).unwrap(),
        );
    }

    #[test]
    fn payload_is_sensitive_to_nonce_and_request() {
        let nonce = [0xAB; 32];
        let base = observer_fetch_signing_payload(&nonce, &request()).unwrap();

        let other_nonce = observer_fetch_signing_payload(&[0xAC; 32], &request()).unwrap();
        assert_ne!(base, other_nonce);

        let mut tampered = request();
        tampered.observer_index = 4;
        assert_ne!(
            base,
            observer_fetch_signing_payload(&nonce, &tampered).unwrap()
        );

        let root_key = ObserverFetchRequest {
            query: ObserverQuery::RootKey,
            ..request()
        };
        assert_ne!(
            base,
            observer_fetch_signing_payload(&nonce, &root_key).unwrap()
        );
    }

    #[test]
    fn payload_starts_with_domain_then_nonce() {
        let nonce = [0xCD; 32];
        let payload = observer_fetch_signing_payload(&nonce, &request()).unwrap();
        assert!(payload.starts_with(OBSERVER_FETCH_DOMAIN));
        assert_eq!(
            &payload[OBSERVER_FETCH_DOMAIN.len()..OBSERVER_FETCH_DOMAIN.len() + 32],
            &nonce
        );
    }
}
