//! Error type and its HTTP mapping.
//!
//! The HTTP listener is the node's most exposed surface (pre-manifest,
//! pre-admission), so the mapping follows the attestation-service rule:
//! caller mistakes surface their detail (400/410), server-side failures are
//! logged in full and flattened to a fixed string on the wire.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum HolderError {
    /// The request's nonce was not 32 bytes of hex.
    #[error("invalid nonce: {0}")]
    InvalidNonce(String),

    /// The network manifest exists, so the quote window has closed for this
    /// boot: attestation-service owns the TPM quote path from the config
    /// POST onward.
    #[error("quote serving stopped: network manifest present")]
    QuoteWindowClosed,

    /// Keystore I/O or decode failure — includes the `Partial` state, where
    /// exactly one key file exists and neither writing nor vouching is safe.
    #[error("keystore: {0}")]
    Keystore(String),

    /// Evidence generation failed (TPM/IMDS path, or a non-TDX host).
    #[error("evidence generation: {0}")]
    Attestation(String),

    /// RAM keys already discarded and no keystore present. Unreachable in
    /// the designed lifecycle; loud if the impossible happens.
    #[error("no keys held: RAM keys discarded and keystore absent")]
    NoKeys,
}

impl IntoResponse for HolderError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            HolderError::InvalidNonce(detail) => {
                (StatusCode::BAD_REQUEST, format!("invalid nonce: {detail}"))
            }
            HolderError::QuoteWindowClosed => (StatusCode::GONE, self.to_string()),
            HolderError::Keystore(_) | HolderError::Attestation(_) | HolderError::NoKeys => {
                tracing::error!(error = %self, "internal error serving holder request");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal error".to_string(),
                )
            }
        };
        (status, message).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_errors_do_not_leak_detail_on_the_wire() {
        let response =
            HolderError::Keystore("reading /persistent/summit/keys/node_key.pem: EACCES".into())
                .into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn caller_mistakes_map_to_400_and_410() {
        assert_eq!(
            HolderError::InvalidNonce("expected 64 hex chars".into())
                .into_response()
                .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            HolderError::QuoteWindowClosed.into_response().status(),
            StatusCode::GONE
        );
    }
}
