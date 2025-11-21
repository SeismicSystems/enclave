use crate::config::InitConfig;
use crate::error::Result;
use crate::server::http::AppState;
use crate::server::validation::{validate_arguments, validate_log_config, validate_ssh_keys};
use axum::response::IntoResponse;
use axum::{Json, extract::State, http::StatusCode, response::Response};

pub async fn handle_config(
    State(state): State<AppState>,
    Json(config): Json<InitConfig>,
) -> Result<Response> {
    validate_ssh_keys(&config.ssh_keys)?;

    if let Some(args) = &config.args {
        validate_arguments(&args)?;
    }

    if let Some(log_config) = &config.log {
        validate_log_config(&log_config)?;
    }

    let mut sender_guard = state.config_sender.lock().await;
    if let Some(sender) = sender_guard.take() {
        let _ = sender.send(config);
    }

    Ok((
        StatusCode::OK,
        "Configuration received and stored successfully".to_string(),
    )
        .into_response())
}
