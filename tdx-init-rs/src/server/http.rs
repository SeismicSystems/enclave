use crate::config::InitConfig;
use crate::error::{Result, TdxInitError};
use crate::server::handlers::handle_config;
use axum::{Router, routing::post};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tracing::info;

const HTTP_PORT: u16 = 8080;

#[derive(Clone)]
pub struct AppState {
    pub config_sender: Arc<tokio::sync::Mutex<Option<oneshot::Sender<InitConfig>>>>,
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
