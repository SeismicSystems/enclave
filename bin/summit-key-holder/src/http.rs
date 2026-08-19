//! The network-facing HTTP surface (plain HTTP; nginx and certbot exist
//! only post-POST, and deploy already polls raw ports pre-manifest).
//!
//! Two GETs, per the founding-harvest wire contract:
//!
//! - `GET /v1/keys` → `{node_public_key, consensus_public_key}` — served
//!   for life; post-persist this feeds deploy's launch-time continuity
//!   assertion (live pubkeys == pinned pubkeys).
//! - `GET /v1/quote?nonce=<64-hex>` → the keys plus attestation evidence
//!   whose `report_data` is `founding_summit_keys_binding(nonce, node_pk,
//!   consensus_pk)`. Deploy archives all three verbatim, together with the
//!   nonce it sent, as this node's harvest record — the document
//!   `verify-quote harvest --record` verifies. Refuses 410 once the network
//!   manifest exists: attestation-service owns the TPM from the config POST
//!   onward.
//!
//! This listener is reachable pre-admission; the node NSG restricts the
//! port to `operator_ip_cidr`, permanently — the conf dir is tmpfs, so the
//! quote window reopens on every boot.

use std::sync::Arc;

use axum::Router;
use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::get;
use seismic_attestation::bindings::{binding64_from_digest32, founding_summit_keys_binding};
use seismic_attestation::{AttestationExchangeMessage, AttestationType, generate_evidence};
use serde::{Deserialize, Serialize};

use crate::error::HolderError;
use crate::state::Holder;

/// Attestation type this build mints evidence for. Azure TDX + vTPM is the
/// only supported type today (mirrors attestation-service).
const ATTESTATION_TYPE: AttestationType = AttestationType::AzureTdx;

#[derive(Serialize, Deserialize)]
pub struct KeysResponse {
    pub node_public_key: String,
    pub consensus_public_key: String,
}

#[derive(Serialize, Deserialize)]
pub struct QuoteResponse {
    pub node_public_key: String,
    pub consensus_public_key: String,
    /// Stored verbatim by deploy's harvest, inside the record it hands to
    /// `verify-quote harvest --record`.
    pub evidence: AttestationExchangeMessage,
}

#[derive(Deserialize)]
struct QuoteParams {
    nonce: String,
}

pub fn router(holder: Arc<Holder>) -> Router {
    Router::new()
        .route("/v1/keys", get(get_keys))
        .route("/v1/quote", get(get_quote))
        .with_state(holder)
}

async fn get_keys(State(holder): State<Arc<Holder>>) -> Result<Json<KeysResponse>, HolderError> {
    let keys = holder.public_keys()?;
    Ok(Json(KeysResponse {
        node_public_key: keys.node_hex(),
        consensus_public_key: keys.consensus_hex(),
    }))
}

async fn get_quote(
    State(holder): State<Arc<Holder>>,
    Query(params): Query<QuoteParams>,
) -> Result<Json<QuoteResponse>, HolderError> {
    if !holder.quote_window_open() {
        return Err(HolderError::QuoteWindowClosed);
    }
    let nonce = parse_nonce(&params.nonce)?;
    let keys = holder.public_keys()?;
    let binding = binding64_from_digest32(founding_summit_keys_binding(
        &nonce,
        &keys.node,
        &keys.consensus,
    ));

    // Evidence generation blocks for seconds (NV write, fixed 3 s sleep,
    // IMDS round-trip) and must not overlap itself, so gate it and push it
    // off the async runtime.
    let _gate = holder.quote_gate.lock().await;
    let evidence =
        tokio::task::spawn_blocking(move || generate_evidence(ATTESTATION_TYPE, binding))
            .await
            .map_err(|e| HolderError::Attestation(format!("evidence task panicked: {e}")))?
            .map_err(|e| HolderError::Attestation(e.to_string()))?;

    Ok(Json(QuoteResponse {
        node_public_key: keys.node_hex(),
        consensus_public_key: keys.consensus_hex(),
        evidence,
    }))
}

/// Parse a harvest nonce: 32 bytes of hex, `0x` optional (the same leniency
/// as `verify-quote`'s hex record fields).
fn parse_nonce(value: &str) -> Result<[u8; 32], HolderError> {
    let stripped = value.strip_prefix("0x").unwrap_or(value);
    let bytes =
        hex::decode(stripped).map_err(|e| HolderError::InvalidNonce(format!("not hex: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| HolderError::InvalidNonce("expected 32 bytes (64 hex chars)".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt as _;
    use std::fs;
    use std::path::Path;
    use tower::ServiceExt as _;

    fn holder(dir: &Path) -> Arc<Holder> {
        Arc::new(Holder::new(
            dir.join("keys"),
            dir.join("network-manifest.json"),
        ))
    }

    async fn get(router: Router, uri: &str) -> (StatusCode, Vec<u8>) {
        let response = router
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, body.to_vec())
    }

    #[tokio::test]
    async fn keys_endpoint_serves_summit_shaped_hex() {
        let dir = tempfile::tempdir().unwrap();
        let (status, body) = get(router(holder(dir.path())), "/v1/keys").await;
        assert_eq!(status, StatusCode::OK);
        let keys: KeysResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(keys.node_public_key.len(), 64);
        assert_eq!(keys.consensus_public_key.len(), 96);
        assert!(!keys.node_public_key.starts_with("0x"));
    }

    #[tokio::test]
    async fn quote_refuses_410_once_manifest_exists() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("network-manifest.json"), "{}").unwrap();
        let (status, _) = get(
            router(holder(dir.path())),
            &format!("/v1/quote?nonce={}", "11".repeat(32)),
        )
        .await;
        assert_eq!(status, StatusCode::GONE);
    }

    #[tokio::test]
    async fn quote_rejects_bad_nonces_before_touching_the_tpm() {
        let dir = tempfile::tempdir().unwrap();
        let router = router(holder(dir.path()));
        for uri in [
            "/v1/quote",                                     // missing param
            "/v1/quote?nonce=zz",                            // not hex
            "/v1/quote?nonce=1122",                          // too short
            &format!("/v1/quote?nonce={}", "11".repeat(33)), // too long
        ] {
            let (status, _) = get(router.clone(), uri).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "uri: {uri}");
        }
    }

    #[test]
    fn nonce_parsing_accepts_optional_0x() {
        let hex64 = "aa".repeat(32);
        assert_eq!(
            parse_nonce(&hex64).unwrap(),
            parse_nonce(&format!("0x{hex64}")).unwrap()
        );
    }
}
