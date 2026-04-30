use axum::{http::StatusCode, response::IntoResponse, response::Response};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TdxInitError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TOML parse error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("Server error: {0}")]
    ServerError(String),
}

pub type Result<T> = std::result::Result<T, TdxInitError>;

impl IntoResponse for TdxInitError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            TdxInitError::Toml(e) => (StatusCode::BAD_REQUEST, format!("Invalid TOML: {e}")),
            TdxInitError::Io(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            ),
            TdxInitError::ServerError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };

        (status, message).into_response()
    }
}
