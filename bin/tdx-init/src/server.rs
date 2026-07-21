use crate::config::InitConfig;
use crate::error::{Result, TdxInitError};
use axum::{
    Router,
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    response::IntoResponse,
    response::Response,
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
        // axum's 2 MiB default is too tight for the config since it embeds
        // the reth genesis: a mainnet-sized alloc is ~1 MiB of JSON, ~1.4 MiB
        // as base64, before the rest of the payload.
        .layer(DefaultBodyLimit::max(16 * 1024 * 1024))
        .with_state(state);

    // This listener is unauthenticated and first-POST-wins. An attacker reaching :8080
    // before the operator can post a malicious config. Make sure to:
    // 1. Only open the port to the operator IP (eg. via firewall ACL).
    // 2. Tear down and redeploy if the POST doesn't return 200 OK
    //    (409 Conflict or connection-refused = someone else won the race).
    //
    // TODO(samlaf): move to a pull-based design to remove the inbound port. Either:
    // 1. Enclave fetches from cloud metadata (eg. UserData in Azure IMDS) - trusts cloud
    // 2. Pull from operator-run service that (whose url/domain would be whitelisted in the TDX image).
    //    This model has the advantage of also being able to have the vault remote attest the TDX
    //    before uploading a config/secret. See https://github.com/flashbots/vault-auth-plugin-attest
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

    // Validate the network artifacts while the operator's POST is still
    // waiting on a response: a bad (or absent) manifest, reth genesis, or peer
    // config must 400 the deploy, not fail at boot when the attestation
    // service/reth try to use them.
    let manifest = crate::manifest::decode_and_validate(&config.network.manifest_base64)?;
    crate::reth_genesis::decode_and_validate(
        &config.network.reth_genesis_base64,
        manifest.chain_id,
    )?;
    crate::peers::validate_and_derive_peers(&config.node, &config.network.bootnodes)?;

    let mut sender_guard = state.config_sender.lock().await;
    match sender_guard.take() {
        Some(sender) => {
            let _ = sender.send(config);
            Ok((
                StatusCode::OK,
                "Configuration received and stored successfully".to_string(),
            )
                .into_response())
        }
        None => Ok((
            StatusCode::CONFLICT,
            "Configuration already received from another caller".to_string(),
        )
            .into_response()),
    }
}
