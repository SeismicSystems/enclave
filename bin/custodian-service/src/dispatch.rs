//! Dispatch for the custodian Unix socket: the shim between the wire
//! protocol and the host's [`CustodianState`].
//!
//! The transport — bind semantics, peer credentials, ACL-before-dispatch,
//! the frame loop — lives in `seismic_custodian_ipc::server`; this module is
//! only the part that must live next to the key: mapping authorized requests
//! onto the custodian state, including the bootstrap transitions through
//! which a joining node acquires its root key.

use crate::state::{CreateAttemptOutcome, CustodianState, InstallOutcome};
use anyhow::Context as _;
use seismic_custodian::{Custodian, VerifiedPeerAuthorization};
use seismic_custodian_ipc::{
    Request, Response, RngIkmBytes, RootKeyBootstrapAttemptBytes, SnapshotKeyBytes,
    TxIoKeypairBytes, TxIoPublicKeyBytes, WrappedRootKeyBytes,
};
use tracing::{error, info, warn};

/// Map one ACL-authorized socket request onto the custodian state.
///
/// One outcome is process-fatal: an installed root key whose LUKS keyfile
/// can't be written exits the host (see the install arm).
pub fn dispatch(state: &CustodianState, request: Request) -> Response {
    match request {
        Request::Ping => Response::Pong,
        Request::GetTxIoKeypair { epoch } => state
            .with_custodian(|custodian| {
                Response::TxIoKeypair(TxIoKeypairBytes {
                    sk: custodian.get_tx_io_sk(epoch).secret_bytes(),
                    pk: custodian.get_tx_io_pk(epoch).serialize(),
                })
            })
            .unwrap_or(Response::RootKeyAbsent),
        Request::GetTxIoPublicKey { epoch } => state
            .with_custodian(|custodian| {
                Response::TxIoPublicKey(TxIoPublicKeyBytes {
                    pk: custodian.get_tx_io_pk(epoch).serialize(),
                })
            })
            .unwrap_or(Response::RootKeyAbsent),
        Request::GetRngIkm { epoch } => state
            .with_custodian(|custodian| {
                Response::RngIkm(RngIkmBytes {
                    ikm: custodian.get_rng_ikm(epoch),
                })
            })
            .unwrap_or(Response::RootKeyAbsent),
        Request::GetSnapshotKey { epoch } => state
            .with_custodian(|custodian| {
                Response::SnapshotKey(SnapshotKeyBytes {
                    key: custodian.get_snapshot_key(epoch).into(),
                })
            })
            .unwrap_or(Response::RootKeyAbsent),
        Request::CreateRootKeyBootstrapAttempt => match state.create_bootstrap_attempt() {
            CreateAttemptOutcome::Created {
                attempt_id,
                requester_eph_pk,
            } => {
                info!("retained a fresh root-key bootstrap attempt");
                Response::RootKeyBootstrapAttemptCreated(RootKeyBootstrapAttemptBytes {
                    attempt_id,
                    requester_eph_pk,
                })
            }
            CreateAttemptOutcome::RootKeyAlreadyPresent => Response::RootKeyAlreadyPresent,
        },
        Request::WrapRootKey {
            root_key_request_binding,
            peer_eph_pk,
        } => match state.with_custodian(|custodian| {
            wrap_root_key(custodian, root_key_request_binding, &peer_eph_pk)
        }) {
            None => Response::RootKeyAbsent,
            Some(Ok(wrapped)) => Response::WrappedRootKey(wrapped),
            Some(Err(error)) => {
                // Detailed failures stay local to the key-holding process.
                // The wire response is stable and cannot accidentally include
                // key bytes from a future lower-level error implementation.
                warn!(?error, "custodian root-key wrap failed");
                Response::Error {
                    message: "root-key wrap failed".to_string(),
                }
            }
        },
        Request::InstallRootKeyFromVerifiedBootstrapResponse {
            attempt_id,
            root_key_request_binding,
            responder_eph_pk,
            wrapped_root_key,
        } => match state.install_root_key(
            attempt_id,
            root_key_request_binding,
            responder_eph_pk,
            &wrapped_root_key,
        ) {
            InstallOutcome::Installed => {
                info!("root key installed; LUKS keyfile written");
                Response::RootKeyInstalled
            }
            InstallOutcome::LuksKeyfileWriteFailed(error) => {
                // Without the LUKS handoff the node can't mount /persistent,
                // so this boot cannot proceed: exit and let the supervisor
                // restart us into a clean re-bootstrap (root_key is RAM-only,
                // so nothing is lost). Skipping the reply is deliberate — the
                // dropped connection tells the caller the exchange died.
                error!(?error, "LUKS keyfile write failed after root-key recovery");
                std::process::exit(1);
            }
            InstallOutcome::RootKeyAlreadyPresent => Response::RootKeyAlreadyPresent,
            InstallOutcome::UnknownAttempt => {
                warn!("root-key install refused: no matching bootstrap attempt");
                Response::Error {
                    message: "no matching bootstrap attempt".to_string(),
                }
            }
            InstallOutcome::InstallFailed(error) => {
                warn!(?error, "custodian root-key install failed");
                Response::Error {
                    message: "root-key install failed".to_string(),
                }
            }
        },
    }
}

fn wrap_root_key(
    custodian: &Custodian,
    root_key_request_binding: [u8; 32],
    peer_eph_pk: &[u8; 33],
) -> anyhow::Result<WrappedRootKeyBytes> {
    let peer_pk = secp256k1::PublicKey::from_slice(peer_eph_pk)
        .context("peer_eph_pk is not a valid compressed secp256k1 point")?;
    let auth = VerifiedPeerAuthorization {
        root_key_request_binding,
    };
    let wrapped = custodian.wrap_root_key_for_peer(&auth, &peer_pk)?;
    Ok(WrappedRootKeyBytes {
        responder_eph_pk: wrapped.responder_eph_pk.serialize(),
        wrapped: wrapped.wrapped,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};

    const ROOT_KEY: [u8; 32] = [7u8; 32];
    const BINDING: [u8; 32] = [0x33; 32];

    fn tmp_luks() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("luks-keys");
        (dir, path)
    }

    fn with_root_key(luks_keyfile: &Path) -> CustodianState {
        CustodianState::new_with_root_key(Custodian::new(ROOT_KEY), luks_keyfile.to_path_buf())
            .expect("write LUKS keyfile")
    }

    fn awaiting(luks_keyfile: &Path) -> CustodianState {
        CustodianState::new_awaiting_root_key(luks_keyfile.to_path_buf())
    }

    #[test]
    fn purpose_keys_match_direct_derivation() {
        let (_dir, luks) = tmp_luks();
        let state = with_root_key(&luks);
        let custodian = Custodian::new(ROOT_KEY);

        let Response::TxIoKeypair(tx_io) = dispatch(&state, Request::GetTxIoKeypair { epoch: 0 })
        else {
            panic!("expected tx-io keypair");
        };
        assert_eq!(tx_io.sk, custodian.get_tx_io_sk(0).secret_bytes());
        assert_eq!(tx_io.pk, custodian.get_tx_io_pk(0).serialize());

        let Response::TxIoPublicKey(tx_io_public) =
            dispatch(&state, Request::GetTxIoPublicKey { epoch: 0 })
        else {
            panic!("expected tx-io public key");
        };
        assert_eq!(tx_io_public.pk, tx_io.pk);

        let Response::RngIkm(rng) = dispatch(&state, Request::GetRngIkm { epoch: 0 }) else {
            panic!("expected rng ikm");
        };
        assert_eq!(rng.ikm, custodian.get_rng_ikm(0));

        let Response::SnapshotKey(snapshot) =
            dispatch(&state, Request::GetSnapshotKey { epoch: 0 })
        else {
            panic!("expected snapshot key");
        };
        let expected: [u8; 32] = custodian.get_snapshot_key(0).into();
        assert_eq!(snapshot.key, expected);
    }

    #[test]
    fn awaiting_root_key_answers_root_key_absent() {
        let (_dir, luks) = tmp_luks();
        let state = awaiting(&luks);
        for request in [
            Request::GetTxIoKeypair { epoch: 0 },
            Request::GetTxIoPublicKey { epoch: 0 },
            Request::GetRngIkm { epoch: 0 },
            Request::GetSnapshotKey { epoch: 0 },
            Request::WrapRootKey {
                root_key_request_binding: BINDING,
                peer_eph_pk: [0; 33],
            },
        ] {
            let method = request.method();
            assert!(
                matches!(dispatch(&state, request), Response::RootKeyAbsent),
                "{method} must answer RootKeyAbsent while awaiting"
            );
        }
    }

    // The full N=2 root-key distribution through dispatch alone: a "genesis"
    // host wraps for a joining host's retained attempt, the joiner installs,
    // then derives the same keys and has written its LUKS keyfile.
    #[test]
    fn bootstrap_over_dispatch_installs_and_writes_luks_keyfile() {
        let (_genesis_dir, genesis_luks) = tmp_luks();
        let (_joiner_dir, joiner_luks) = tmp_luks();
        let genesis = with_root_key(&genesis_luks);
        let joiner = awaiting(&joiner_luks);

        let Response::RootKeyBootstrapAttemptCreated(attempt) =
            dispatch(&joiner, Request::CreateRootKeyBootstrapAttempt)
        else {
            panic!("expected a created attempt");
        };
        let Response::WrappedRootKey(wrapped) = dispatch(
            &genesis,
            Request::WrapRootKey {
                root_key_request_binding: BINDING,
                peer_eph_pk: attempt.requester_eph_pk,
            },
        ) else {
            panic!("expected a wrapped root key");
        };
        let installed = dispatch(
            &joiner,
            Request::InstallRootKeyFromVerifiedBootstrapResponse {
                attempt_id: attempt.attempt_id,
                root_key_request_binding: BINDING,
                responder_eph_pk: wrapped.responder_eph_pk,
                wrapped_root_key: wrapped.wrapped,
            },
        );
        assert!(matches!(installed, Response::RootKeyInstalled));

        // The joiner now derives the genesis keys...
        let Response::TxIoKeypair(joiner_keys) =
            dispatch(&joiner, Request::GetTxIoKeypair { epoch: 0 })
        else {
            panic!("expected tx-io keypair");
        };
        assert_eq!(
            joiner_keys.sk,
            Custodian::new(ROOT_KEY).get_tx_io_sk(0).secret_bytes()
        );

        // ...and wrote the LUKS keyfile on install: 64 bytes, mode 0400.
        let metadata = std::fs::metadata(&joiner_luks).expect("keyfile written");
        assert_eq!(metadata.len(), 64);
        assert_eq!(metadata.permissions().mode() & 0o777, 0o400);

        // Restart probe: a fresh create now reports the key present.
        assert!(matches!(
            dispatch(&joiner, Request::CreateRootKeyBootstrapAttempt),
            Response::RootKeyAlreadyPresent
        ));
    }

    #[test]
    fn install_failures_return_stable_sanitized_errors() {
        let (_dir, luks) = tmp_luks();
        let joiner = awaiting(&luks);

        let Response::Error { message } = dispatch(
            &joiner,
            Request::InstallRootKeyFromVerifiedBootstrapResponse {
                attempt_id: [1; 32],
                root_key_request_binding: BINDING,
                responder_eph_pk: [3; 33],
                wrapped_root_key: vec![4; 60],
            },
        ) else {
            panic!("expected a sanitized error");
        };
        assert_eq!(message, "no matching bootstrap attempt");

        // A garbage responder point on a live attempt: sanitized failure, no
        // secp256k1/AEAD detail on the wire.
        let Response::RootKeyBootstrapAttemptCreated(attempt) =
            dispatch(&joiner, Request::CreateRootKeyBootstrapAttempt)
        else {
            panic!("expected a created attempt");
        };
        let Response::Error { message } = dispatch(
            &joiner,
            Request::InstallRootKeyFromVerifiedBootstrapResponse {
                attempt_id: attempt.attempt_id,
                root_key_request_binding: BINDING,
                responder_eph_pk: [0; 33],
                wrapped_root_key: vec![0; 60],
            },
        ) else {
            panic!("expected a sanitized error");
        };
        assert_eq!(message, "root-key install failed");
    }

    #[test]
    fn wrap_root_key_rejects_invalid_peer_point() {
        let (_dir, luks) = tmp_luks();
        let state = with_root_key(&luks);
        let response = dispatch(
            &state,
            Request::WrapRootKey {
                root_key_request_binding: [0u8; 32],
                peer_eph_pk: [0u8; 33],
            },
        );
        let Response::Error { message } = response else {
            panic!("expected sanitized custodian error");
        };
        assert_eq!(message, "root-key wrap failed");
    }

    /// Coverage over real `UnixListener`s: two served custodians — one
    /// genesis, one joining — complete the root-key distribution through the
    /// crate server + async client, exactly the calls the attestation service
    /// will make (attestation itself deliberately absent: evidence never
    /// reaches the custodian). Needs an environment permitting `AF_UNIX`
    /// bind; in a sandbox that forbids it, skip with `-- --skip real_socket`.
    mod real_socket {
        use super::*;
        use crate::state::CustodianState;
        use seismic_custodian_ipc::server::{MethodAcl, bind, serve};
        use seismic_custodian_ipc::{
            CreateRootKeyBootstrapAttemptResult, CustodianClient,
            InstallRootKeyFromVerifiedBootstrapResponseResult, IpcError,
        };

        fn spawn_host(state: CustodianState, dir: &tempfile::TempDir) -> PathBuf {
            let socket = dir.path().join("custodian.sock");
            let listener = bind(&socket).expect("bind");
            std::thread::spawn(move || {
                serve(listener, MethodAcl::own_uid_only(), move |request| {
                    dispatch(&state, request)
                })
            });
            socket
        }

        #[tokio::test]
        async fn full_bootstrap_between_two_custodians() {
            let genesis_dir = tempfile::tempdir().expect("tempdir");
            let joiner_dir = tempfile::tempdir().expect("tempdir");
            let genesis_socket = spawn_host(
                with_root_key(&genesis_dir.path().join("luks-keys")),
                &genesis_dir,
            );
            let joiner_socket =
                spawn_host(awaiting(&joiner_dir.path().join("luks-keys")), &joiner_dir);

            let mut genesis = CustodianClient::connect(&genesis_socket)
                .await
                .expect("connect");
            let mut joiner = CustodianClient::connect(&joiner_socket)
                .await
                .expect("connect");

            // Before bootstrap, the joiner serves no keys.
            let error = joiner.get_tx_io_keypair(0).await.expect_err("no key yet");
            assert!(matches!(error, IpcError::RootKeyAbsent));

            let CreateRootKeyBootstrapAttemptResult::Created(attempt) = joiner
                .create_root_key_bootstrap_attempt()
                .await
                .expect("create attempt")
            else {
                panic!("joiner must not already hold a root key");
            };

            // The attestation service's role in between — verifying evidence
            // and computing the transcript binding — is opaque to both
            // custodians; any 32 bytes stand in for the binding here.
            let wrapped = genesis
                .wrap_root_key(BINDING, attempt.requester_eph_pk)
                .await
                .expect("wrap root key");

            let installed = joiner
                .install_root_key_from_verified_bootstrap_response(
                    attempt.attempt_id,
                    BINDING,
                    wrapped.responder_eph_pk,
                    wrapped.wrapped,
                )
                .await
                .expect("install root key");
            assert_eq!(
                installed,
                InstallRootKeyFromVerifiedBootstrapResponseResult::Installed
            );

            // Both custodians now serve identical purpose keys.
            let genesis_keys = genesis.get_tx_io_keypair(0).await.expect("genesis keys");
            let joiner_keys = joiner.get_tx_io_keypair(0).await.expect("joiner keys");
            assert_eq!(genesis_keys.sk, joiner_keys.sk);

            // The joiner wrote its LUKS keyfile on install.
            let metadata =
                std::fs::metadata(joiner_dir.path().join("luks-keys")).expect("keyfile written");
            assert_eq!(metadata.len(), 64);

            // Restarted-service probe: create against a custodian holding the
            // key reports it present instead of erroring.
            let probe = joiner
                .create_root_key_bootstrap_attempt()
                .await
                .expect("probe");
            assert!(matches!(
                probe,
                CreateRootKeyBootstrapAttemptResult::RootKeyAlreadyPresent
            ));
        }
    }
}
