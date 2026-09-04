use crate::error::{Result, TdxInitError};
use crate::writer;
use axum::{
    Router,
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    response::IntoResponse,
    response::Response,
    routing::post,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tdx_init_config::InitConfig;
use tokio::fs;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tracing::info;

const HTTP_PORT: u16 = 8080;

#[derive(Clone)]
struct AppState {
    config_sender: Arc<tokio::sync::Mutex<Option<oneshot::Sender<InitConfig>>>>,
    conf_dir: PathBuf,
    sentinel_file: PathBuf,
}

/// Run the one-shot config HTTP server.
///
/// Persists service files and the sentinel **before** returning HTTP 200, so a
/// successful response means the config is actually on disk. On persistence
/// failure the oneshot sender is restored so the operator can POST again in the
/// same process lifetime (see issue #265).
pub async fn run_initialization_server(
    conf_dir: &Path,
    sentinel_file: &Path,
) -> Result<InitConfig> {
    let (config_tx, config_rx) = oneshot::channel();

    let state = AppState {
        config_sender: Arc::new(tokio::sync::Mutex::new(Some(config_tx))),
        conf_dir: conf_dir.to_path_buf(),
        sentinel_file: sentinel_file.to_path_buf(),
    };

    let app = Router::new()
        .route("/", post(handle_config))
        // axum's 2 MiB default is too tight for the config since it embeds
        // the reth genesis: a mainnet-sized alloc is ~1 MiB of JSON, ~1.4 MiB
        // as base64, before the rest of the payload.
        .layer(DefaultBodyLimit::max(16 * 1024 * 1024))
        .with_state(state);

    // This listener is unauthenticated and first-POST-wins (after a successful
    // persist). An attacker reaching :8080 before the operator can post a
    // malicious config. Make sure to:
    // 1. Only open the port to the operator IP (eg. via firewall ACL).
    // 2. Tear down and redeploy if the POST doesn't return 200 OK
    //    (409 Conflict or connection-refused = someone else won the race;
    //     500 = persistence failed and retry is allowed).
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
    // waiting on a response: a bad (or absent) manifest, reth genesis, summit
    // genesis, or peer config must 400 the deploy, not fail at boot when the
    // attestation service/reth/summit try to use them.
    let manifest = crate::manifest::decode_and_validate(&config.network.manifest_base64)?;
    crate::reth_genesis::decode_and_validate(
        &config.network.reth_genesis_base64,
        manifest.chain_id,
    )?;
    crate::summit_genesis::decode_and_validate(
        &config.network.summit_genesis_base64,
        &manifest.namespace,
    )?;
    crate::peers::validate_and_derive_peers(&config.node, &config.network.bootnodes)?;

    let mut sender_guard = state.config_sender.lock().await;
    match sender_guard.take() {
        Some(sender) => {
            // Persist before acknowledging. A 200 must mean files + sentinel
            // are on disk; otherwise restore the sender so the operator can
            // retry without restarting tdx-init.
            if let Err(err) = persist_config(&state.conf_dir, &state.sentinel_file, &config).await
            {
                *sender_guard = Some(sender);
                return Err(err);
            }

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

async fn persist_config(
    conf_dir: &Path,
    sentinel_file: &Path,
    config: &InitConfig,
) -> Result<()> {
    writer::write_service_configs(conf_dir, config).await?;
    fs::write(sentinel_file, b"").await?;
    Ok(())
}
