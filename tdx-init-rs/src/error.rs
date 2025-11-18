use axum::{http::StatusCode, response::IntoResponse, response::Response};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TdxInitError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Invalid SSH key format at index {index}: {key}")]
    InvalidSshKey { index: usize, key: String },

    #[error("SSH keys array cannot be empty")]
    EmptyKeys,

    #[error("LUKS operation failed: {0}")]
    LuksError(String),

    #[error("Command execution failed: {cmd} - {stderr}")]
    CommandError { cmd: String, stderr: String },

    #[error("MAC verification failed")]
    MacVerificationFailed,

    #[error("Config not found: {0}")]
    ConfigNotFound(String),

    #[error("Server error: {0}")]
    ServerError(String),

    #[error("Device already mounted")]
    AlreadyMounted,

    #[error("SSH key file not found")]
    SshKeyNotFound,

    #[error("Glob error: {0}")]
    GlobPatternError(glob::PatternError),

    #[error("Glob error: {0}")]
    GlobError(glob::GlobError),
}

pub type Result<T> = std::result::Result<T, TdxInitError>;

impl IntoResponse for TdxInitError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            TdxInitError::EmptyKeys => (
                StatusCode::BAD_REQUEST,
                "ssh_keys array cannot be empty".to_string(),
            ),
            TdxInitError::InvalidSshKey { index, .. } => (
                StatusCode::BAD_REQUEST,
                format!(
                    "Invalid ssh_keys[{}] format, expected base64-encoded OpenSSH ed25519 public key",
                    index
                ),
            ),
            TdxInitError::Json(_) => (StatusCode::BAD_REQUEST, "Invalid JSON format".to_string()),
            TdxInitError::Io(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            ),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            ),
        };

        (status, message).into_response()
    }
}
