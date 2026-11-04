use axum::{http::StatusCode, response::IntoResponse, response::Response};
use thiserror::Error;

#[derive(Error, Debug)]
pub(crate) enum TdxInitError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TOML parse error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error(transparent)]
    InvalidNetwork(#[from] tdx_init_config::InvalidNetwork),

    #[error("invalid peer config: {0}")]
    InvalidPeers(String),

    /// The custodian's candidate tx_io_pk file exists but cannot be read: an
    /// image fault (a missing group grant), not an operator error.
    #[error("{0}")]
    CandidateTxIoPk(#[from] seismic_custodian_ipc::candidate_tx_io_pk::CandidateTxIoPkFileError),

    #[error("Server error: {0}")]
    ServerError(String),
}

pub(crate) type Result<T> = std::result::Result<T, TdxInitError>;

impl IntoResponse for TdxInitError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            TdxInitError::Toml(e) => (StatusCode::BAD_REQUEST, format!("Invalid TOML: {e}")),
            // An operator config error: fail the deploy POST loudly rather
            // than surfacing at a later boot.
            TdxInitError::InvalidNetwork(e) => (StatusCode::BAD_REQUEST, with_sources(&e)),
            TdxInitError::InvalidPeers(msg) => (
                StatusCode::BAD_REQUEST,
                format!("invalid peer config: {msg}"),
            ),
            TdxInitError::Io(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            ),
            TdxInitError::CandidateTxIoPk(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("reading the custodian's candidate tx_io_pk@0: {e}"),
            ),
            TdxInitError::ServerError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };

        (status, message).into_response()
    }
}

/// `err` and its causes, outermost first, as `what: why: ...`. The operator
/// sees only the response body, so it carries the whole chain, not the
/// outermost message alone (`invalid reth genesis`).
fn with_sources(err: &dyn std::error::Error) -> String {
    let mut message = err.to_string();
    let mut source = err.source();
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use tdx_init_config::{InvalidNetwork, InvalidRethGenesis};

    #[test]
    fn a_400_body_carries_the_cause() {
        let err = InvalidNetwork::from(InvalidRethGenesis::ChainIdMismatch {
            found: 5125,
            expected: 5124,
        });
        assert_eq!(
            with_sources(&err),
            "invalid reth genesis: config.chainId 5125 does not match the manifest's eth.chain_id \
             5124"
        );
    }
}
