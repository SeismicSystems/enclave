use axum::{http::StatusCode, response::IntoResponse, response::Response};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TdxInitError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TOML parse error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("invalid network manifest: {0}")]
    InvalidManifest(String),

    #[error("invalid reth genesis: {0}")]
    InvalidRethGenesis(String),

    #[error("invalid summit genesis: {0}")]
    InvalidSummitGenesis(String),

    #[error("invalid peer config: {0}")]
    InvalidPeers(String),

    /// The custodian's candidate tx_io_pk file exists but cannot be read: an
    /// image fault (a missing group grant), not an operator error.
    #[error("{0}")]
    CandidateTxIoPk(#[from] seismic_custodian_ipc::candidate_tx_io_pk::CandidateTxIoPkFileError),

    #[error("Server error: {0}")]
    ServerError(String),
}

pub type Result<T> = std::result::Result<T, TdxInitError>;

impl IntoResponse for TdxInitError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            TdxInitError::Toml(e) => (StatusCode::BAD_REQUEST, format!("Invalid TOML: {e}")),
            // An operator config error: fail the deploy POST loudly rather
            // than surfacing at a later boot.
            TdxInitError::InvalidManifest(msg) => (
                StatusCode::BAD_REQUEST,
                format!("invalid network manifest: {msg}"),
            ),
            TdxInitError::InvalidRethGenesis(msg) => (
                StatusCode::BAD_REQUEST,
                format!("invalid reth genesis: {msg}"),
            ),
            TdxInitError::InvalidSummitGenesis(msg) => (
                StatusCode::BAD_REQUEST,
                format!("invalid summit genesis: {msg}"),
            ),
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
