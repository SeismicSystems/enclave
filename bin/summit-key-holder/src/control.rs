//! The persist control socket — deliberately not the network listener.
//!
//! One operation, `persist`: write the keystore if absent, confirm it if
//! present, discard the RAM keys either way. summit.service's
//! `ExecStartPre=summit-key-holder persist-wait` blocks on it — this is
//! the sole provisioner of summit's keystore, so summit never starts
//! before the pinned keys are on disk.
//!
//! This socket is the future custody-split boundary: if the holder is ever
//! split into a socket-only custody process plus a secret-free HTTP front,
//! the protocol here — and its `persist-wait` client — does not change.
//!
//! Wire format is one JSON line per direction over a per-request
//! connection. No secret ever crosses this socket (responses carry public
//! keys only), so the custodian's length-prefixed-CBOR/zeroize transport
//! discipline would buy nothing here; a debuggable text protocol wins.
//! systemd-tmpfiles creates the socket directory; both ends run as the
//! `summit` user, so the socket itself is 0600.

use std::io::ErrorKind;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, info, warn};

use crate::state::{Holder, PersistOutcome};

/// Default control socket path. The `/run/summit-key-holder` tmpfs
/// directory is created by systemd-tmpfiles from a snippet in
/// seismic-images; `bind` also creates it as a fallback for local runs.
pub const DEFAULT_CONTROL_SOCKET_PATH: &str = "/run/summit-key-holder/control.sock";

/// A request line must fit comfortably in one read; anything longer is not
/// this protocol.
const MAX_REQUEST_LINE: u64 = 1024;

/// How long `persist-wait` sleeps between connection attempts while the
/// holder is not up yet.
const PERSIST_WAIT_RETRY: Duration = Duration::from_millis(500);

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "op", rename_all = "kebab-case")]
pub enum ControlRequest {
    Persist,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "result", rename_all = "kebab-case")]
pub enum ControlResponse {
    /// First boot: keystore written from this boot's RAM keys.
    Persisted {
        node_public_key: String,
        consensus_public_key: String,
    },
    /// Reboot: existing keystore decoded cleanly; RAM keys discarded.
    Confirmed {
        node_public_key: String,
        consensus_public_key: String,
    },
    /// Definitive failure (partial keystore, unwritable dir, …). The
    /// client must exit nonzero, failing summit's start loudly.
    Failed { error: String },
}

impl From<Result<PersistOutcome, crate::error::HolderError>> for ControlResponse {
    fn from(result: Result<PersistOutcome, crate::error::HolderError>) -> Self {
        match result {
            Ok(outcome) => {
                let keys = outcome.public_keys();
                let (node_public_key, consensus_public_key) =
                    (keys.node_hex(), keys.consensus_hex());
                match outcome {
                    PersistOutcome::Persisted(_) => ControlResponse::Persisted {
                        node_public_key,
                        consensus_public_key,
                    },
                    PersistOutcome::Confirmed(_) => ControlResponse::Confirmed {
                        node_public_key,
                        consensus_public_key,
                    },
                }
            }
            Err(e) => ControlResponse::Failed {
                error: e.to_string(),
            },
        }
    }
}

/// Bind the control socket, clearing a previous run's stale inode (same
/// rationale as the custodian socket's bind).
pub fn bind(path: &Path) -> std::io::Result<UnixListener> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = UnixListener::bind(path)?;
    // 0600: the only legitimate client is persist-wait running as the same
    // (summit) user from summit.service's ExecStartPre.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    info!("control socket listening on {}", path.display());
    Ok(listener)
}

/// Accept loop: one request line per connection, one response line back.
/// Never returns.
pub async fn serve(listener: UnixListener, holder: Arc<Holder>) {
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(e) => {
                warn!("control socket accept failed: {e}");
                continue;
            }
        };
        let holder = Arc::clone(&holder);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, holder).await {
                warn!("control connection failed: {e}");
            }
        });
    }
}

/// Generic over the stream so the protocol is testable over an in-memory
/// duplex; only [`serve`] touches real sockets (the custodian-ipc split).
async fn handle_connection<S>(stream: S, holder: Arc<Holder>) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite,
{
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut line = String::new();
    BufReader::new(read_half.take(MAX_REQUEST_LINE))
        .read_line(&mut line)
        .await
        .context("reading request line")?;

    let response = match serde_json::from_str::<ControlRequest>(&line) {
        Ok(ControlRequest::Persist) => {
            // Keystore writes hit the persistent disk (sync_all); keep them
            // off the async runtime.
            let response: ControlResponse = tokio::task::spawn_blocking(move || holder.persist())
                .await
                .context("persist task panicked")?
                .into();
            if let ControlResponse::Failed { error } = &response {
                warn!("persist failed: {error}");
            } else {
                info!("persist: {response:?}");
            }
            response
        }
        Err(e) => ControlResponse::Failed {
            error: format!("unrecognized request: {e}"),
        },
    };

    let mut bytes = serde_json::to_vec(&response).context("encoding response")?;
    bytes.push(b'\n');
    write_half
        .write_all(&bytes)
        .await
        .context("writing response line")?;
    Ok(())
}

/// The `persist-wait` client: block until the holder reports the keystore
/// written (first boot) or confirmed (reboot); exit nonzero on a definitive
/// failure. Connection errors mean the holder is not up yet and are
/// retried forever — systemd's start timeout is the backstop.
pub async fn persist_wait(path: &Path) -> anyhow::Result<ControlResponse> {
    loop {
        let stream = match UnixStream::connect(path).await {
            Ok(stream) => stream,
            Err(e) => {
                debug!("holder not reachable at {} ({e}); retrying", path.display());
                tokio::time::sleep(PERSIST_WAIT_RETRY).await;
                continue;
            }
        };
        // Past this point errors are protocol failures, not "not up yet":
        // fail loudly rather than mask a broken holder by retrying.
        return persist_once(stream).await;
    }
}

async fn persist_once<S>(stream: S) -> anyhow::Result<ControlResponse>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite,
{
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut request = serde_json::to_vec(&ControlRequest::Persist)?;
    request.push(b'\n');
    write_half
        .write_all(&request)
        .await
        .context("sending persist request")?;

    let mut line = String::new();
    BufReader::new(read_half)
        .read_line(&mut line)
        .await
        .context("reading persist response")?;
    let response: ControlResponse =
        serde_json::from_str(&line).context("decoding persist response")?;
    match &response {
        ControlResponse::Failed { error } => anyhow::bail!("holder refused persist: {error}"),
        _ => Ok(response),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_holder(dir: &Path) -> Arc<Holder> {
        Arc::new(Holder::new(
            dir.join("keys"),
            dir.join("network-manifest.json"),
        ))
    }

    /// Drive one client request against `handle_connection` over an
    /// in-memory duplex — the protocol without a real socket.
    async fn persist_over_duplex(holder: &Arc<Holder>) -> anyhow::Result<ControlResponse> {
        let (client, server) = tokio::io::duplex(4096);
        let server_holder = Arc::clone(holder);
        let server_task = tokio::spawn(handle_connection(server, server_holder));
        let response = persist_once(client).await;
        server_task.await.unwrap().unwrap();
        response
    }

    #[tokio::test]
    async fn persist_protocol_round_trips_first_boot_and_reboot() {
        let dir = tempfile::tempdir().unwrap();
        let holder = test_holder(dir.path());

        let expected = holder.public_keys().unwrap();
        match persist_over_duplex(&holder).await.unwrap() {
            ControlResponse::Persisted {
                node_public_key,
                consensus_public_key,
            } => {
                assert_eq!(node_public_key, expected.node_hex());
                assert_eq!(consensus_public_key, expected.consensus_hex());
            }
            other => panic!("expected Persisted, got {other:?}"),
        }

        // Second persist over the same keystore confirms.
        match persist_over_duplex(&holder).await.unwrap() {
            ControlResponse::Confirmed {
                node_public_key, ..
            } => {
                assert_eq!(node_public_key, expected.node_hex());
            }
            other => panic!("expected Confirmed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn persist_fails_loudly_on_a_partial_keystore() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("keys")).unwrap();
        std::fs::write(dir.path().join("keys/node_key.pem"), "00").unwrap();
        let holder = test_holder(dir.path());

        let err = persist_over_duplex(&holder).await.unwrap_err().to_string();
        assert!(err.contains("partial keystore"), "got: {err}");
    }

    #[tokio::test]
    async fn garbage_requests_get_a_failed_response_not_a_hang() {
        let dir = tempfile::tempdir().unwrap();
        let holder = test_holder(dir.path());

        let (client, server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(handle_connection(server, holder));
        let (read_half, mut write_half) = tokio::io::split(client);
        write_half
            .write_all(b"{\"op\":\"launch-missiles\"}\n")
            .await
            .unwrap();
        let mut line = String::new();
        BufReader::new(read_half)
            .read_line(&mut line)
            .await
            .unwrap();
        let response: ControlResponse = serde_json::from_str(&line).unwrap();
        assert!(matches!(response, ControlResponse::Failed { .. }));
        server_task.await.unwrap().unwrap();
    }

    /// End-to-end over a real socket: bind, serve, persist-wait. Requires
    /// an environment that permits AF_UNIX binds (CI does; some sandboxes
    /// don't — the duplex tests above cover the protocol there).
    #[tokio::test(flavor = "multi_thread")]
    async fn persist_wait_round_trips_over_a_real_socket() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("control.sock");
        let holder = test_holder(dir.path());
        let listener = bind(&socket).unwrap();
        tokio::spawn(serve(listener, Arc::clone(&holder)));

        let expected = holder.public_keys().unwrap();
        match persist_wait(&socket).await.unwrap() {
            ControlResponse::Persisted {
                node_public_key, ..
            } => {
                assert_eq!(node_public_key, expected.node_hex());
            }
            other => panic!("expected Persisted, got {other:?}"),
        }
    }
}
