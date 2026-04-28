use axum::{http::StatusCode, response::IntoResponse, response::Response};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TdxInitError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Server error: {0}")]
    ServerError(String),

    #[error("Invalid argument for {binary}: argument '{arg}' conflicts with default configuration")]
    ConflictingArgument { binary: String, arg: String },

    #[error(
        "Invalid log level '{level}' for {binary}: must be one of trace, debug, info, warn, error"
    )]
    InvalidLogLevel { binary: String, level: String },
}

pub type Result<T> = std::result::Result<T, TdxInitError>;

impl IntoResponse for TdxInitError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            TdxInitError::Json(_) => (StatusCode::BAD_REQUEST, "Invalid JSON format".to_string()),
            TdxInitError::Io(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            ),
            TdxInitError::ConflictingArgument { binary, arg } => (
                StatusCode::BAD_REQUEST,
                format!(
                    "Argument '{}' for {} conflicts with default configuration",
                    arg, binary
                ),
            ),
            TdxInitError::InvalidLogLevel { binary, level } => (
                StatusCode::BAD_REQUEST,
                format!(
                    "Invalid log level '{}' for {}: must be one of trace, debug, info, warn, error",
                    level, binary
                ),
            ),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            ),
        };

        (status, message).into_response()
    }
}
