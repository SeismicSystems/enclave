//! The founding harvest: summit's public keys, the custodian's candidate
//! `tx_io_pk@0`, and a quote over them, on `--operator-listen` (`:7879` in the
//! image).
//!
//! Two GETs, per the founding-harvest wire contract:
//!
//! - `GET /v1/keys` → `{node_public_key, consensus_public_key}` — served
//!   for life; post-persist this feeds deploy's launch-time continuity
//!   assertion (live pubkeys == pinned pubkeys).
//! - `GET /v1/quote?nonce=<64-hex>` → the keys, the `tx_io_pk@0` of the
//!   custodian's candidate root key, and attestation evidence whose
//!   `report_data` is `founding_keys_binding(nonce, node_pk, consensus_pk,
//!   candidate_tx_io_pk)`. Deploy archives all four verbatim, together with the
//!   nonce it sent, as this node's harvest record — the document
//!   `seismic-verify-quote`'s `verify_harvest` (the deploy CLI's `verify
//!   harvest`) verifies. Refuses 410 once the network manifest exists.
//!
//! The keys come from the public-keys file the image's summit setup units
//! write: `summit-keygen` from the tmpfs keys it generated at boot, and
//! `summit-persist` from the keystore once it has copied or confirmed it. The
//! candidate's `tx_io_pk@0` comes from the candidate tx_io_pk file the
//! custodian writes when it mints at startup. This service never sees a private
//! key; it quotes the public halves the files name, under a binding it builds
//! itself.
//!
//! The listener is up before the config POST, so it is reachable
//! pre-admission; the node's firewall restricts the port to the operator's
//! CIDR, permanently — the conf dir is tmpfs, so the quote window reopens on
//! every boot.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::Router;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use seismic_attestation::bindings::{binding64_from_digest32, founding_keys_binding};
use seismic_attestation::{AttestationExchangeMessage, generate_evidence};
use seismic_custodian_ipc::candidate_tx_io_pk;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::net::TcpListener;

use crate::ATTESTATION_TYPE;

/// Where the image's summit setup units write the node's summit public keys,
/// as `summit keys show --json` prints them.
pub const SUMMIT_PUBLIC_KEYS_PATH: &str = "/run/seismic/summit/public-keys.json";

/// Summit's public keys: the shape of the public-keys file, of `/v1/keys`,
/// and the leading fields of `/v1/quote`. Bare lowercase hex, exactly as
/// summit renders them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeysResponse {
    pub node_public_key: String,
    pub consensus_public_key: String,
}

#[derive(Serialize, Deserialize)]
pub struct QuoteResponse {
    pub node_public_key: String,
    pub consensus_public_key: String,
    /// The custodian's candidate `tx_io_pk@0`, 33-byte compressed SEC1 hex.
    /// Assemble pins one box's in the manifest.
    pub candidate_tx_io_public_key: String,
    /// Stored verbatim by deploy's harvest, inside the record it hands to
    /// `seismic-verify-quote`'s `verify_harvest`.
    pub evidence: AttestationExchangeMessage,
}

#[derive(Deserialize)]
struct QuoteParams {
    nonce: String,
}

/// Caller mistakes surface their detail (400/410); server-side failures are
/// logged in full and flattened to a fixed string on the wire.
#[derive(Error, Debug)]
pub(crate) enum HarvestError {
    #[error("invalid nonce: {0}")]
    InvalidNonce(String),

    /// The network manifest exists, so the quote window has closed for this
    /// boot.
    #[error("quote serving stopped: network manifest present")]
    QuoteWindowClosed,

    /// `summit-keygen` has not written the public-keys file yet.
    #[error("summit public keys not yet written")]
    NoSummitPublicKeys,

    /// The public-keys file exists but cannot be read or decoded.
    #[error("summit public keys: {0}")]
    SummitPublicKeys(String),

    /// The custodian has not written its candidate tx_io_pk file yet.
    #[error("candidate tx_io_pk@0 not yet written")]
    NoCandidateTxIoPk,

    /// The candidate tx_io_pk file exists but cannot be read or decoded.
    #[error("candidate tx_io_pk@0: {0}")]
    CandidateTxIoPk(String),

    /// Evidence generation failed (TPM/IMDS path, or a non-TDX host).
    #[error("evidence generation: {0}")]
    Attestation(String),
}

impl IntoResponse for HarvestError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            HarvestError::InvalidNonce(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            HarvestError::QuoteWindowClosed => (StatusCode::GONE, self.to_string()),
            HarvestError::NoSummitPublicKeys | HarvestError::NoCandidateTxIoPk => {
                (StatusCode::SERVICE_UNAVAILABLE, self.to_string())
            }
            HarvestError::SummitPublicKeys(_)
            | HarvestError::CandidateTxIoPk(_)
            | HarvestError::Attestation(_) => {
                tracing::error!(error = %self, "internal error serving harvest request");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal error".to_string(),
                )
            }
        };
        (status, message).into_response()
    }
}

pub(crate) struct Harvest {
    summit_public_keys_path: PathBuf,
    manifest_path: PathBuf,
    candidate_tx_io_pk_path: PathBuf,
    /// Serializes this listener's evidence generation: the vTPM quote path is
    /// exclusive-open on `/dev/tpm0` and takes seconds per call.
    quote_gate: tokio::sync::Mutex<()>,
}

impl Harvest {
    pub(crate) fn new(
        summit_public_keys_path: PathBuf,
        manifest_path: PathBuf,
        candidate_tx_io_pk_path: PathBuf,
    ) -> Self {
        Self {
            summit_public_keys_path,
            manifest_path,
            candidate_tx_io_pk_path,
            quote_gate: tokio::sync::Mutex::new(()),
        }
    }

    /// Read per request, since `summit-persist` rewrites the file from the
    /// keystore once LUKS opens.
    fn summit_public_keys(&self) -> Result<KeysResponse, HarvestError> {
        read_json(&self.summit_public_keys_path)
            .ok_or(HarvestError::NoSummitPublicKeys)?
            .map_err(HarvestError::SummitPublicKeys)
    }

    /// Read per request, since a custodian restart re-mints and rewrites it.
    fn candidate_tx_io_public_key(&self) -> Result<[u8; 33], HarvestError> {
        candidate_tx_io_pk::read(&self.candidate_tx_io_pk_path)
            .map_err(|e| HarvestError::CandidateTxIoPk(e.to_string()))?
            .ok_or(HarvestError::NoCandidateTxIoPk)
    }

    /// A per-request stat of the tmpfs path is the freshest possible check.
    fn quote_window_open(&self) -> bool {
        !self.manifest_path.exists()
    }
}

pub(crate) fn router(harvest: Arc<Harvest>) -> Router {
    Router::new()
        .route("/v1/keys", get(get_keys))
        .route("/v1/quote", get(get_quote))
        .with_state(harvest)
}

/// Serve the harvest on `listener` until the server fails.
pub(crate) async fn serve(listener: TcpListener, harvest: Harvest) -> anyhow::Result<()> {
    axum::serve(listener, router(Arc::new(harvest))).await?;
    anyhow::bail!("harvest server exited unexpectedly")
}

async fn get_keys(State(harvest): State<Arc<Harvest>>) -> Result<Json<KeysResponse>, HarvestError> {
    Ok(Json(harvest.summit_public_keys()?))
}

async fn get_quote(
    State(harvest): State<Arc<Harvest>>,
    Query(params): Query<QuoteParams>,
) -> Result<Json<QuoteResponse>, HarvestError> {
    if !harvest.quote_window_open() {
        return Err(HarvestError::QuoteWindowClosed);
    }
    let nonce = parse_nonce(&params.nonce)?;
    let keys = harvest.summit_public_keys()?;
    let node_pk: [u8; 32] = decode_key(&keys.node_public_key, "node_public_key")?;
    let consensus_pk: [u8; 48] = decode_key(&keys.consensus_public_key, "consensus_public_key")?;
    let candidate_tx_io_pk = harvest.candidate_tx_io_public_key()?;
    let binding = binding64_from_digest32(founding_keys_binding(
        &nonce,
        &node_pk,
        &consensus_pk,
        &candidate_tx_io_pk,
    ));

    // Evidence generation blocks for seconds (NV write, fixed 3 s sleep,
    // IMDS round-trip), so it runs off the async runtime, one at a time.
    let _gate = harvest.quote_gate.lock().await;
    let evidence =
        tokio::task::spawn_blocking(move || generate_evidence(ATTESTATION_TYPE, binding))
            .await
            .map_err(|e| HarvestError::Attestation(format!("evidence task panicked: {e}")))?
            .map_err(|e| HarvestError::Attestation(e.to_string()))?;
    // Evidence generation takes seconds: recheck, so a config POST landing
    // meanwhile closes the window for this request too.
    if !harvest.quote_window_open() {
        return Err(HarvestError::QuoteWindowClosed);
    }

    Ok(Json(QuoteResponse {
        node_public_key: keys.node_public_key,
        consensus_public_key: keys.consensus_public_key,
        candidate_tx_io_public_key: hex::encode(candidate_tx_io_pk),
        evidence,
    }))
}

/// Parse a harvest nonce: 32 bytes of hex, `0x` optional (the same leniency
/// as `seismic-verify-quote`'s hex record fields).
fn parse_nonce(value: &str) -> Result<[u8; 32], HarvestError> {
    let stripped = value.strip_prefix("0x").unwrap_or(value);
    let bytes =
        hex::decode(stripped).map_err(|e| HarvestError::InvalidNonce(format!("not hex: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| HarvestError::InvalidNonce("expected 32 bytes (64 hex chars)".to_string()))
}

/// `None` while the file does not exist yet, `Some(Err(detail))` when it
/// cannot be read or decoded: each caller maps both to its own errors.
fn read_json<T: DeserializeOwned>(path: &Path) -> Option<Result<T, String>> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(error) => return Some(Err(format!("reading {}: {error}", path.display()))),
    };
    Some(
        serde_json::from_slice(&bytes)
            .map_err(|error| format!("decoding {}: {error}", path.display())),
    )
}

fn decode_key<const N: usize>(value: &str, field: &str) -> Result<[u8; N], HarvestError> {
    let bytes = hex::decode(value)
        .map_err(|e| HarvestError::SummitPublicKeys(format!("{field}: not hex: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| HarvestError::SummitPublicKeys(format!("{field}: expected {N} bytes")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt as _;
    use std::fs;
    use std::path::Path;
    use tower::ServiceExt as _;

    const KEYS_JSON: &str = r#"{"node_public_key":"1111111111111111111111111111111111111111111111111111111111111111","consensus_public_key":"222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222"}"#;

    fn router_in(dir: &Path) -> Router {
        router(Arc::new(Harvest::new(
            dir.join("public-keys.json"),
            dir.join("network-manifest.json"),
            dir.join("candidate-tx-io-pk"),
        )))
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

    fn quote_uri() -> String {
        format!("/v1/quote?nonce={}", "11".repeat(32))
    }

    #[tokio::test]
    async fn keys_endpoint_serves_the_summit_public_keys_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("public-keys.json"), KEYS_JSON).unwrap();
        let (status, body) = get(router_in(dir.path()), "/v1/keys").await;
        assert_eq!(status, StatusCode::OK);
        let served: KeysResponse = serde_json::from_slice(&body).unwrap();
        let written: KeysResponse = serde_json::from_str(KEYS_JSON).unwrap();
        assert_eq!(served, written);
    }

    #[tokio::test]
    async fn missing_summit_public_keys_are_503() {
        let dir = tempfile::tempdir().unwrap();
        let (status, _) = get(router_in(dir.path()), "/v1/keys").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        let (status, _) = get(router_in(dir.path()), &quote_uri()).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }

    // A wrong-length key never reaches the TPM, and its detail stays off the wire.
    #[tokio::test]
    async fn malformed_summit_public_keys_are_500_before_touching_the_tpm() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("public-keys.json"),
            r#"{"node_public_key":"11","consensus_public_key":"22"}"#,
        )
        .unwrap();
        let (status, body) = get(router_in(dir.path()), &quote_uri()).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body, b"internal error");
    }

    #[tokio::test]
    async fn quote_refuses_410_once_manifest_exists() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("public-keys.json"), KEYS_JSON).unwrap();
        fs::write(dir.path().join("network-manifest.json"), "{}").unwrap();
        let (status, _) = get(router_in(dir.path()), &quote_uri()).await;
        assert_eq!(status, StatusCode::GONE);
        // /v1/keys keeps serving for the launch checks.
        let (status, _) = get(router_in(dir.path()), "/v1/keys").await;
        assert_eq!(status, StatusCode::OK);
    }

    // No candidate, no quote: the harvest must never see summit keys quoted
    // without the candidate key beside them.
    #[tokio::test]
    async fn a_missing_candidate_tx_io_pk_is_503() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("public-keys.json"), KEYS_JSON).unwrap();
        let (status, body) = get(router_in(dir.path()), &quote_uri()).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body, b"candidate tx_io_pk@0 not yet written");
    }

    #[tokio::test]
    async fn a_malformed_candidate_tx_io_pk_is_500_before_touching_the_tpm() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("public-keys.json"), KEYS_JSON).unwrap();
        fs::write(dir.path().join("candidate-tx-io-pk"), [0x02u8; 32]).unwrap();
        let (status, body) = get(router_in(dir.path()), &quote_uri()).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body, b"internal error");
    }

    #[tokio::test]
    async fn quote_rejects_bad_nonces_before_touching_the_tpm() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("public-keys.json"), KEYS_JSON).unwrap();
        let router = router_in(dir.path());
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
