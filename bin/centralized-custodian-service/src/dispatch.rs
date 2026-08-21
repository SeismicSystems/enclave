//! Unix-socket dispatch for the centralized custodian.
//!
//! Epoch 0 of every purpose derives from the keyfile root exactly like the
//! TDX custodian, so consumers see identical bytes across the two services.
//! Epochs >= 1 derive the same way, but from the COUNCIL-DELIVERED root for
//! that epoch; an epoch whose root has not been delivered answers the typed
//! [`Response::EpochKeyUnavailable`] so callers can retry after delivery —
//! except in observer mode, where the custodian first tries to fetch the
//! missing epoch from its parent custodian (bounded by the parent I/O
//! timeouts, so a hung parent degrades to the same typed error).
//! The root-key bootstrap methods answer a stable error: this service runs
//! standalone, holds its root key from a local keyfile, and never
//! participates in the attested bootstrap exchange.

use crate::observer::ParentFetcher;
use crate::state::CentralizedCustodianState;
use seismic_custodian::Custodian;
use seismic_custodian_ipc::{
    Request, Response, RngIkmBytes, SnapshotKeyBytes, TxIoKeypairBytes, TxIoPublicKeyBytes,
};
use tracing::warn;

/// Map one ACL-authorized socket request onto the centralized state.
/// `fetcher` is `Some` only in observer mode.
pub fn dispatch(
    state: &CentralizedCustodianState,
    fetcher: Option<&ParentFetcher>,
    request: Request,
) -> Response {
    match request {
        Request::Ping => Response::Pong,
        Request::GetTxIoKeypair { epoch: 0 } => {
            let custodian = state.custodian();
            Response::TxIoKeypair(TxIoKeypairBytes {
                sk: custodian.get_tx_io_sk(0).secret_bytes(),
                pk: custodian.get_tx_io_pk(0).serialize(),
            })
        }
        Request::GetTxIoPublicKey { epoch: 0 } => Response::TxIoPublicKey(TxIoPublicKeyBytes {
            pk: state.custodian().get_tx_io_pk(0).serialize(),
        }),
        Request::GetRngIkm { epoch: 0 } => Response::RngIkm(RngIkmBytes {
            ikm: state.custodian().get_rng_ikm(0),
        }),
        Request::GetSnapshotKey { epoch: 0 } => Response::SnapshotKey(SnapshotKeyBytes {
            key: state.custodian().get_snapshot_key(0).into(),
        }),
        Request::GetTxIoKeypair { epoch } => serve_epoch_key(state, fetcher, epoch, |custodian| {
            Response::TxIoKeypair(TxIoKeypairBytes {
                sk: custodian.get_tx_io_sk(epoch).secret_bytes(),
                pk: custodian.get_tx_io_pk(epoch).serialize(),
            })
        }),
        // The public key exists only once the epoch root was delivered, so
        // an undelivered epoch is EpochKeyUnavailable here too.
        Request::GetTxIoPublicKey { epoch } => {
            serve_epoch_key(state, fetcher, epoch, |custodian| {
                Response::TxIoPublicKey(TxIoPublicKeyBytes {
                    pk: custodian.get_tx_io_pk(epoch).serialize(),
                })
            })
        }
        Request::GetRngIkm { epoch } => serve_epoch_key(state, fetcher, epoch, |custodian| {
            Response::RngIkm(RngIkmBytes {
                ikm: custodian.get_rng_ikm(epoch),
            })
        }),
        Request::GetSnapshotKey { epoch } => serve_epoch_key(state, fetcher, epoch, |custodian| {
            Response::SnapshotKey(SnapshotKeyBytes {
                key: custodian.get_snapshot_key(epoch).into(),
            })
        }),
        Request::CreateRootKeyBootstrapAttempt
        | Request::WrapRootKey { .. }
        | Request::InstallRootKeyFromVerifiedBootstrapResponse { .. } => {
            warn!(
                method = request.method(),
                "bootstrap method called on the standalone centralized custodian"
            );
            Response::Error {
                message: "the centralized custodian does not participate in root-key bootstrap"
                    .to_string(),
            }
        }
    }
}

/// Serve one epoch >= 1 request from the custodian holding that epoch's
/// delivered root. Derivations cannot fail here: every root is validated to
/// derive cleanly for all purposes before it is installed.
fn serve_epoch_key(
    state: &CentralizedCustodianState,
    fetcher: Option<&ParentFetcher>,
    epoch: u64,
    f: impl FnOnce(&Custodian) -> Response,
) -> Response {
    // In observer mode, a locally missing epoch triggers a parent fetch
    // first — outside `with_epoch_custodian`, so the store mutex is never
    // held across network I/O. Failures degrade to the same typed
    // availability error the caller would have gotten anyway.
    if epoch >= 1
        && let Some(fetcher) = fetcher
        && state.with_epoch_custodian(epoch, |_| ()).is_none()
    {
        match fetcher.fetch_up_to(state, epoch) {
            Ok(true) => {}
            Ok(false) => return Response::EpochKeyUnavailable { epoch },
            Err(e) => {
                warn!(
                    error = %format!("{e:#}"),
                    epoch,
                    "on-demand fetch from parent custodian failed"
                );
                return Response::EpochKeyUnavailable { epoch };
            }
        }
    }
    match state.with_epoch_custodian(epoch, f) {
        Some(response) => response,
        None => Response::EpochKeyUnavailable { epoch },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{EPOCH_ROOT, ROOT_KEY, build_state, seal};
    use seismic_council_delivery::CouncilResponse;
    use seismic_custodian::Custodian;

    #[test]
    fn epoch_zero_serves_root_key_derivations() {
        let dir = tempfile::tempdir().unwrap();
        let state = build_state(dir.path());
        let custodian = Custodian::new(ROOT_KEY);

        let Response::TxIoKeypair(keys) =
            dispatch(&state, None, Request::GetTxIoKeypair { epoch: 0 })
        else {
            panic!("expected tx-io keypair");
        };
        assert_eq!(keys.sk, custodian.get_tx_io_sk(0).secret_bytes());

        let Response::RngIkm(rng) = dispatch(&state, None, Request::GetRngIkm { epoch: 0 }) else {
            panic!("expected rng ikm");
        };
        assert_eq!(rng.ikm, custodian.get_rng_ikm(0));

        let Response::SnapshotKey(snapshot) =
            dispatch(&state, None, Request::GetSnapshotKey { epoch: 0 })
        else {
            panic!("expected snapshot key");
        };
        let expected: [u8; 32] = custodian.get_snapshot_key(0).into();
        assert_eq!(snapshot.key, expected);

        assert!(matches!(
            dispatch(&state, None, Request::Ping),
            Response::Pong
        ));
    }

    #[test]
    fn bootstrap_methods_answer_a_stable_error() {
        let dir = tempfile::tempdir().unwrap();
        let state = build_state(dir.path());
        for request in [
            Request::CreateRootKeyBootstrapAttempt,
            Request::WrapRootKey {
                root_key_request_binding: [0; 32],
                peer_eph_pk: [0; 33],
            },
            Request::InstallRootKeyFromVerifiedBootstrapResponse {
                attempt_id: [0; 32],
                root_key_request_binding: [0; 32],
                responder_eph_pk: [0; 33],
                wrapped_root_key: Vec::new(),
            },
        ] {
            let method = request.method();
            let Response::Error { message } = dispatch(&state, None, request) else {
                panic!("{method} must answer a stable error");
            };
            assert_eq!(
                message,
                "the centralized custodian does not participate in root-key bootstrap"
            );
        }
    }

    #[test]
    fn undelivered_epochs_answer_epoch_key_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let state = build_state(dir.path());
        for request in [
            Request::GetTxIoKeypair { epoch: 1 },
            Request::GetTxIoPublicKey { epoch: 1 },
            Request::GetRngIkm { epoch: 1 },
            Request::GetSnapshotKey { epoch: 2 },
        ] {
            let method = request.method();
            let response = dispatch(&state, None, request);
            assert!(
                matches!(response, Response::EpochKeyUnavailable { .. }),
                "{method} must answer EpochKeyUnavailable, got {}",
                response.kind()
            );
        }
    }

    #[test]
    fn delivered_epochs_serve_keys_derived_from_the_epoch_root() {
        let dir = tempfile::tempdir().unwrap();
        let state = build_state(dir.path());
        assert!(matches!(
            state.deliver(&seal(1, EPOCH_ROOT)),
            CouncilResponse::Delivered { .. }
        ));

        // One delivered root serves every purpose of the epoch, each key
        // HKDF-derived exactly as a custodian over that root derives it.
        let epoch_custodian = Custodian::new(EPOCH_ROOT);

        let Response::TxIoKeypair(keys) =
            dispatch(&state, None, Request::GetTxIoKeypair { epoch: 1 })
        else {
            panic!("expected tx-io keypair");
        };
        assert_eq!(keys.sk, epoch_custodian.get_tx_io_sk(1).secret_bytes());
        assert_eq!(keys.pk, epoch_custodian.get_tx_io_pk(1).serialize());

        let Response::TxIoPublicKey(pk) =
            dispatch(&state, None, Request::GetTxIoPublicKey { epoch: 1 })
        else {
            panic!("expected tx-io public key");
        };
        assert_eq!(pk.pk, epoch_custodian.get_tx_io_pk(1).serialize());

        let Response::RngIkm(rng) = dispatch(&state, None, Request::GetRngIkm { epoch: 1 }) else {
            panic!("expected rng ikm");
        };
        assert_eq!(rng.ikm, epoch_custodian.get_rng_ikm(1));

        let Response::SnapshotKey(snapshot) =
            dispatch(&state, None, Request::GetSnapshotKey { epoch: 1 })
        else {
            panic!("expected snapshot key");
        };
        let expected: [u8; 32] = epoch_custodian.get_snapshot_key(1).into();
        assert_eq!(snapshot.key, expected);

        // Epoch 0 still answers from derivation, unaffected by deliveries.
        let Response::TxIoKeypair(epoch0) =
            dispatch(&state, None, Request::GetTxIoKeypair { epoch: 0 })
        else {
            panic!("expected tx-io keypair");
        };
        assert_eq!(
            epoch0.sk,
            Custodian::new(ROOT_KEY).get_tx_io_sk(0).secret_bytes()
        );
    }

    /// Coverage over real sockets: the council delivers over TCP, then the
    /// custodian's async client fetches the delivered epoch over the served
    /// unix socket — exactly the two wire paths the shipped binary runs.
    /// Needs an environment permitting `AF_UNIX`/TCP bind; in a sandbox that
    /// forbids them, skip with `-- --skip real_socket`.
    mod real_socket {
        use super::*;
        use crate::council::serve_council;
        use crate::test_support::build_state;
        use seismic_council_delivery::{CouncilRequest, CouncilResponse};
        use seismic_custodian_ipc::server::{MethodAcl, bind};
        use seismic_custodian_ipc::{
            CustodianClient, IpcError, read_frame_blocking, write_frame_blocking,
        };
        use std::sync::Arc;

        fn council_call(addr: std::net::SocketAddr, request: &CouncilRequest) -> CouncilResponse {
            let mut stream = std::net::TcpStream::connect(addr).expect("connect council port");
            write_frame_blocking(&mut stream, request).expect("send council request");
            read_frame_blocking(&mut stream)
                .expect("read council response")
                .expect("council response frame")
        }

        #[tokio::test]
        async fn delivery_over_tcp_serves_over_the_unix_socket() {
            let dir = tempfile::tempdir().expect("tempdir");
            let state = Arc::new(build_state(dir.path()));

            let socket_path = dir.path().join("custodian.sock");
            let unix_listener = bind(&socket_path).expect("bind unix socket");
            let unix_state = state.clone();
            std::thread::spawn(move || {
                seismic_custodian_ipc::server::serve(
                    unix_listener,
                    MethodAcl::own_uid_only(),
                    move |request| dispatch(&unix_state, None, request),
                )
            });

            let tcp_listener =
                std::net::TcpListener::bind("127.0.0.1:0").expect("bind council port");
            let council_addr = tcp_listener.local_addr().expect("council addr");
            let council_state = state.clone();
            std::thread::spawn(move || serve_council(tcp_listener, council_state, None));

            // Before delivery: epoch 1 is a typed, retriable error.
            let mut client = CustodianClient::connect(&socket_path)
                .await
                .expect("connect");
            let error = client
                .get_tx_io_keypair(1)
                .await
                .expect_err("not delivered");
            assert!(matches!(error, IpcError::EpochKeyUnavailable { epoch: 1 }));

            // The council asks for status (next epoch), delivers.
            let CouncilResponse::Status(status) =
                council_call(council_addr, &CouncilRequest::GetStatus)
            else {
                panic!("expected status");
            };
            assert_eq!(status.epoch, 0);
            let response = council_call(
                council_addr,
                &CouncilRequest::DeliverEpochKey(seal(1, EPOCH_ROOT)),
            );
            assert!(matches!(response, CouncilResponse::Delivered { epoch: 1 }));

            // The delivered epoch now serves keys derived from its root;
            // epoch 0 still derives from the keyfile; epoch 2 stays
            // unavailable.
            let keys = client.get_tx_io_keypair(1).await.expect("delivered epoch");
            assert_eq!(
                keys.sk,
                Custodian::new(EPOCH_ROOT).get_tx_io_sk(1).secret_bytes()
            );
            let epoch0 = client.get_tx_io_keypair(0).await.expect("derived epoch");
            assert_eq!(
                epoch0.sk,
                Custodian::new(ROOT_KEY).get_tx_io_sk(0).secret_bytes()
            );
            let error = client
                .get_tx_io_keypair(2)
                .await
                .expect_err("not delivered");
            assert!(matches!(error, IpcError::EpochKeyUnavailable { epoch: 2 }));
        }

        /// The full observer topology: council delivers to the PARENT over
        /// TCP; the OBSERVER boots against it (root key fetched + persisted,
        /// envelope backfill) and serves over its own unix socket, fetching
        /// later epochs from the parent on demand.
        #[tokio::test]
        async fn observer_boots_from_parent_and_serves_on_demand() {
            use crate::observer::{ParentFetcher, obtain_root_key};
            use crate::test_support::{CHAIN_ID, MASTER_SEED, network_id, observer_serving};
            use seismic_observer_key::observer_namespace_from_chain_id;

            // Parent: state + observer serving on a real TCP port; the
            // council delivers epoch 1 before the observer boots.
            let parent_dir = tempfile::tempdir().expect("tempdir");
            let parent = Arc::new(build_state(parent_dir.path()));
            let serving = Arc::new(observer_serving(parent_dir.path()));
            let tcp_listener =
                std::net::TcpListener::bind("127.0.0.1:0").expect("bind council port");
            let parent_addr = tcp_listener.local_addr().expect("parent addr");
            let parent_council = parent.clone();
            std::thread::spawn(move || serve_council(tcp_listener, parent_council, Some(serving)));
            let response = council_call(
                parent_addr,
                &CouncilRequest::DeliverEpochKey(seal(1, EPOCH_ROOT)),
            );
            assert!(matches!(response, CouncilResponse::Delivered { .. }));

            // Observer boot, exactly as main() sequences it: root key from
            // the parent, state, backfill, then the unix socket.
            let observer_dir = tempfile::tempdir().expect("tempdir");
            let fetcher = Arc::new(ParentFetcher::new(
                &MASTER_SEED,
                &observer_namespace_from_chain_id(CHAIN_ID),
                0,
                parent_addr.to_string(),
                network_id(),
            ));
            let root_key_path = observer_dir.path().join("root.key");
            let root_key = obtain_root_key(&fetcher, &root_key_path).expect("root key from parent");
            assert_eq!(root_key, ROOT_KEY);
            let observer = Arc::new(
                CentralizedCustodianState::new(
                    Custodian::new(root_key),
                    observer_dir.path().join("deliveries"),
                    crate::test_support::council_keys().1,
                    network_id(),
                )
                .expect("observer state"),
            );
            fetcher.backfill(&observer).expect("backfill");

            let socket_path = observer_dir.path().join("custodian.sock");
            let unix_listener = bind(&socket_path).expect("bind unix socket");
            let unix_state = observer.clone();
            let unix_fetcher = fetcher.clone();
            std::thread::spawn(move || {
                seismic_custodian_ipc::server::serve(
                    unix_listener,
                    MethodAcl::own_uid_only(),
                    move |request| dispatch(&unix_state, Some(&unix_fetcher), request),
                )
            });
            let mut client = CustodianClient::connect(&socket_path)
                .await
                .expect("connect");

            // Backfilled epoch and derived epoch 0 both serve, with the
            // same bytes the parent would give.
            let keys = client.get_tx_io_keypair(1).await.expect("backfilled");
            assert_eq!(
                keys.sk,
                Custodian::new(EPOCH_ROOT).get_tx_io_sk(1).secret_bytes()
            );
            let epoch0 = client.get_tx_io_keypair(0).await.expect("derived");
            assert_eq!(
                epoch0.sk,
                Custodian::new(ROOT_KEY).get_tx_io_sk(0).secret_bytes()
            );

            // A new epoch delivered to the PARENT only is fetched on demand
            // when the observer's socket is asked for it...
            let response = council_call(
                parent_addr,
                &CouncilRequest::DeliverEpochKey(seal(2, [0x51; 32])),
            );
            assert!(matches!(response, CouncilResponse::Delivered { .. }));
            let keys = client.get_tx_io_keypair(2).await.expect("on-demand fetch");
            assert_eq!(
                keys.sk,
                Custodian::new([0x51; 32]).get_tx_io_sk(2).secret_bytes()
            );
            // ...and was persisted locally on the way through.
            assert_eq!(observer.status().epoch, 2);

            // An epoch nobody has stays a typed, retriable error.
            let error = client
                .get_tx_io_keypair(9)
                .await
                .expect_err("undelivered everywhere");
            assert!(matches!(error, IpcError::EpochKeyUnavailable { epoch: 9 }));
        }
    }
}
