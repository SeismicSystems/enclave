use crate::config::InitConfig;
use crate::error::{Result, TdxInitError};
use axum::{
    Router, extract::State, http::StatusCode, response::IntoResponse, response::Response,
    routing::post,
};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tracing::info;

const HTTP_PORT: u16 = 8080;

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

    // TODO: this listener is unauthenticated and first-POST-wins. An
    // attacker reaching :8080 ahead of the operator can write malicious
    // config (e.g., attacker-controlled enclave peers → `root_key`
    // exfiltration during bootstrap). Today's only defense is cloud-
    // firewall ACLs restricting :8080 to the operator's IP. Fix candidates:
    // - RA-TLS (operator verifies TDX quote in cert before posting)
    // - cloud-metadata-pull (no inbound port; operator posts to cloud metadata service using cloud CLI)
    // - signed payloads with image-baked verifier pubkey
    let listener = TcpListener::bind(format!("0.0.0.0:{}", HTTP_PORT)).await?;
    info!("HTTP server listening on port {}", HTTP_PORT);

    tokio::select! {
        config = config_rx => {
            config.map_err(|_| TdxInitError::ServerError(
                "Server closed without receiving config".to_string(),
            ))
        }
        result = axum::serve(listener, app) => {
            result?;
            Err(TdxInitError::ServerError("Server exited unexpectedly".to_string()))
        }
    }
}

async fn handle_config(State(state): State<AppState>, body: String) -> Result<Response> {
    let config: InitConfig = toml::from_str(&body)?;

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
