use crate::config::{ArgsConfig, InitConfig, LogConfig};
use crate::error::{Result, TdxInitError};
use axum::response::IntoResponse;
use axum::{Json, Router, extract::State, http::StatusCode, response::Response, routing::post};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tracing::info;

const HTTP_PORT: u16 = 8080;
const VALID_LOG_LEVELS: &[&str] = &["trace", "debug", "info", "warn", "error"];

#[derive(Clone)]
struct AppState {
    config_sender: Arc<tokio::sync::Mutex<Option<oneshot::Sender<InitConfig>>>>,
}

pub async fn run_initialization_server() -> Result<InitConfig> {
    let (config_tx, config_rx) = oneshot::channel();

    let state = AppState {
        config_sender: Arc::new(tokio::sync::Mutex::new(Some(config_tx))),
    };

    let app = Router::new()
        .route("/", post(handle_config))
        .with_state(state);

    let listener = TcpListener::bind(format!("0.0.0.0:{}", HTTP_PORT)).await?;
    info!("HTTP server listening on port {}", HTTP_PORT);

    tokio::select! {
        config = config_rx => {
            config.map_err(|_| TdxInitError::ServerError("Server closed without receiving config".to_string()))
        }
        result = axum::serve(listener, app) => {
            result?;
            Err(TdxInitError::ServerError("Server exited unexpectedly".to_string()))
        }
    }
}

async fn handle_config(
    State(state): State<AppState>,
    Json(config): Json<InitConfig>,
) -> Result<Response> {
    if let Some(args) = &config.args {
        validate_arguments(args)?;
    }

    if let Some(log_config) = &config.log {
        validate_log_config(log_config)?;
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

fn validate_arguments(args: &ArgsConfig) -> Result<()> {
    let default_args = crate::config::DefaultArgs::new();

    if let Some(reth_args) = &args.reth {
        validate_binary_args("reth", reth_args, &default_args.get_reth_flag_names())?;
    }

    if let Some(summit_args) = &args.summit {
        validate_binary_args("summit", summit_args, &default_args.get_summit_flag_names())?;
    }

    if let Some(enclave_args) = &args.enclave {
        validate_binary_args(
            "enclave",
            enclave_args,
            &default_args.get_enclave_flag_names(),
        )?;
    }

    Ok(())
}

fn validate_log_config(log_config: &LogConfig) -> Result<()> {
    if let Some(summit_level) = &log_config.summit {
        validate_log_level("summit", summit_level)?;
    }

    if let Some(reth_level) = &log_config.reth {
        validate_log_level("reth", reth_level)?;
    }

    if let Some(enclave_level) = &log_config.enclave {
        validate_log_level("enclave", enclave_level)?;
    }

    Ok(())
}

fn validate_binary_args(binary: &str, user_args: &str, default_flags: &[&str]) -> Result<()> {
    let user_tokens: Vec<&str> = user_args.split_whitespace().collect();

    for user_token in &user_tokens {
        if !user_token.starts_with('-') {
            continue;
        }

        let flag_name = if let Some(eq_pos) = user_token.find('=') {
            &user_token[..eq_pos]
        } else {
            user_token
        };

        if default_flags.contains(&flag_name) {
            return Err(TdxInitError::ConflictingArgument {
                binary: binary.to_string(),
                arg: flag_name.to_string(),
            });
        }
    }

    Ok(())
}

fn validate_log_level(binary: &str, level: &str) -> Result<()> {
    if !VALID_LOG_LEVELS.contains(&level.to_lowercase().as_str()) {
        return Err(TdxInitError::InvalidLogLevel {
            binary: binary.to_string(),
            level: level.to_string(),
        });
    }
    Ok(())
}
