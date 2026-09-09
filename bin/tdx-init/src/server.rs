use crate::error::{Result, TdxInitError};
use axum::{
    Router,
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    response::IntoResponse,
    response::Response,
    routing::post,
};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tdx_init_config::InitConfig;
use tokio::{fs, net::TcpListener, sync::oneshot};
use tracing::{error, info};

const HTTP_PORT: u16 = 8080;

#[derive(Clone)]
struct AppState {
    completion_senders: Arc<tokio::sync::Mutex<Option<CompletionSenders>>>,
    conf_dir: Arc<PathBuf>,
    sentinel_file: Arc<PathBuf>,
}

struct CompletionSenders {
    result: oneshot::Sender<Result<()>>,
    shutdown: oneshot::Sender<()>,
}

pub async fn run_initialization_server(conf_dir: &Path, sentinel_file: &Path) -> Result<()> {
    let (result_tx, result_rx) = oneshot::channel();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    let state = AppState {
        completion_senders: Arc::new(tokio::sync::Mutex::new(Some(CompletionSenders {
            result: result_tx,
            shutdown: shutdown_tx,
        }))),
        conf_dir: Arc::new(conf_dir.to_path_buf()),
        sentinel_file: Arc::new(sentinel_file.to_path_buf()),
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

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = shutdown_rx.await;
        })
        .await?;

    result_rx.await.map_err(|_| {
        TdxInitError::ServerError("Server closed without persisting config".to_string())
    })?
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

    let completion = {
        let mut sender_guard = state.completion_senders.lock().await;
        sender_guard.take()
    };
    let Some(completion) = completion else {
        return Ok((
            StatusCode::CONFLICT,
            "Configuration already received from another caller".to_string(),
        )
            .into_response());
    };

    // Keep the request open until every service file and the final sentinel
    // are durable from tdx-init's point of view. Once a valid caller wins the
    // first-POST race, persistence failure is terminal for this process: the
    // caller receives 500, the server shuts down, and systemd can restart it.
    let persistence = async {
        crate::writer::write_service_configs(state.conf_dir.as_path(), &config).await?;
        fs::write(state.sentinel_file.as_path(), b"").await?;
        Ok(())
    }
    .await;

    let response = match &persistence {
        Ok(()) => (
            StatusCode::OK,
            "Configuration received and stored successfully".to_string(),
        )
            .into_response(),
        Err(error) => {
            error!(%error, "failed to persist received configuration");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            )
                .into_response()
        }
    };

    // Graceful shutdown lets this in-flight response reach the caller before
    // run_initialization_server returns the persistence result to main.
    let _ = completion.result.send(persistence);
    let _ = completion.shutdown.send(());
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use tdx_init_config::{DomainConfig, NetworkConfig, NodeConfig};
    use tempfile::TempDir;

    fn sample_config() -> InitConfig {
        InitConfig {
            network: NetworkConfig {
                manifest_base64: base64::engine::general_purpose::STANDARD.encode(include_bytes!(
                    "../../../crates/network-manifest/fixtures/network-manifest-v1.json"
                )),
                reth_genesis_base64: base64::engine::general_purpose::STANDARD.encode(
                    crate::reth_genesis::tests::genesis_json(
                        crate::reth_genesis::tests::FIXTURE_CHAIN_ID,
                    ),
                ),
                summit_genesis_base64: base64::engine::general_purpose::STANDARD.encode(
                    crate::summit_genesis::tests::genesis_toml(
                        crate::summit_genesis::tests::FIXTURE_NAMESPACE,
                    ),
                ),
                bootnodes: vec![],
            },
            node: NodeConfig {
                external_ip: "203.0.113.1".to_string(),
                genesis_node: true,
                domain: DomainConfig {
                    email: "ops@example.com".to_string(),
                    name: "node1.example.com".to_string(),
                },
            },
        }
    }

    fn test_state(
        conf_dir: PathBuf,
        sentinel_file: PathBuf,
    ) -> (
        AppState,
        oneshot::Receiver<Result<()>>,
        oneshot::Receiver<()>,
    ) {
        let (result_tx, result_rx) = oneshot::channel();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        (
            AppState {
                completion_senders: Arc::new(tokio::sync::Mutex::new(Some(CompletionSenders {
                    result: result_tx,
                    shutdown: shutdown_tx,
                }))),
                conf_dir: Arc::new(conf_dir),
                sentinel_file: Arc::new(sentinel_file),
            },
            result_rx,
            shutdown_rx,
        )
    }

    #[tokio::test]
    async fn acknowledges_only_after_files_and_sentinel_are_persisted() {
        let tmp = TempDir::new().unwrap();
        let sentinel = tmp.path().join(".tdx-init-done");
        let (state, result_rx, shutdown_rx) =
            test_state(tmp.path().to_path_buf(), sentinel.clone());

        let response = handle_config(State(state), toml::to_string(&sample_config()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(result_rx.await.unwrap().is_ok());
        shutdown_rx.await.unwrap();
        assert!(sentinel.exists());
        assert!(tmp.path().join("domain.env").exists());
    }

    #[tokio::test]
    async fn persistence_failure_returns_500_and_requires_restart() {
        let tmp = TempDir::new().unwrap();
        let not_a_directory = tmp.path().join("not-a-directory");
        fs::write(&not_a_directory, b"occupied").await.unwrap();
        let sentinel = not_a_directory.join(".tdx-init-done");
        let (state, result_rx, shutdown_rx) = test_state(not_a_directory, sentinel.clone());

        let response = handle_config(
            State(state.clone()),
            toml::to_string(&sample_config()).unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(result_rx.await.unwrap().is_err());
        shutdown_rx.await.unwrap();
        assert!(!sentinel.exists());

        let retry = handle_config(State(state), toml::to_string(&sample_config()).unwrap())
            .await
            .unwrap();
        assert_eq!(retry.status(), StatusCode::CONFLICT);
    }
}
