//! Unix-socket dispatch for the centralized custodian.
//!
//! Epoch 0 of every purpose — and everything that isn't an epoch-key fetch
//! (ping, the bootstrap trio) — delegates verbatim to the base custodian's
//! dispatch, so those behaviors stay byte-identical with the standalone
//! service. Epochs >= 1 of tx-io/rng/snapshot are served only from
//! council-delivered keys; a key not delivered yet answers the typed
//! [`Response::EpochKeyUnavailable`] so callers can retry after delivery.

use crate::state::{CentralizedCustodianState, EpochKeyLookup};
use anyhow::Result;
use seismic_council_delivery::DeliveryPurpose;
use seismic_custodian::Key;
use seismic_custodian_ipc::{
    Request, Response, RngIkmBytes, SnapshotKeyBytes, TxIoKeypairBytes, TxIoPublicKeyBytes,
};
use tracing::error;

/// Map one ACL-authorized socket request onto the centralized state.
pub fn dispatch(state: &CentralizedCustodianState, request: Request) -> Response {
    match request {
        Request::GetTxIoKeypair { epoch } if epoch >= 1 => {
            serve_epoch_key(state, DeliveryPurpose::TxIo, epoch, |key| {
                let (sk, pk) = key.to_secp256k1_keypair()?;
                Ok(Response::TxIoKeypair(TxIoKeypairBytes {
                    sk: sk.secret_bytes(),
                    pk: pk.serialize(),
                }))
            })
        }
        // The public key exists only once the secret was delivered, so an
        // undelivered epoch is EpochKeyUnavailable here too.
        Request::GetTxIoPublicKey { epoch } if epoch >= 1 => {
            serve_epoch_key(state, DeliveryPurpose::TxIo, epoch, |key| {
                let (_, pk) = key.to_secp256k1_keypair()?;
                Ok(Response::TxIoPublicKey(TxIoPublicKeyBytes {
                    pk: pk.serialize(),
                }))
            })
        }
        Request::GetRngIkm { epoch } if epoch >= 1 => {
            serve_epoch_key(state, DeliveryPurpose::RngPrecompile, epoch, |key| {
                Ok(Response::RngIkm(RngIkmBytes {
                    ikm: key.to_rng_ikm()?,
                }))
            })
        }
        Request::GetSnapshotKey { epoch } if epoch >= 1 => {
            serve_epoch_key(state, DeliveryPurpose::Snapshot, epoch, |key| {
                Ok(Response::SnapshotKey(SnapshotKeyBytes {
                    key: key.to_snapshot_key().into(),
                }))
            })
        }
        other => seismic_custodian_service::dispatch::dispatch(state.base(), other),
    }
}

fn serve_epoch_key(
    state: &CentralizedCustodianState,
    purpose: DeliveryPurpose,
    epoch: u64,
    f: impl FnOnce(&Key) -> Result<Response>,
) -> Response {
    match state.with_epoch_key(purpose, epoch, f) {
        EpochKeyLookup::Ok(Ok(response)) => response,
        // Defensive only: keys are conversion-validated at delivery time.
        EpochKeyLookup::Ok(Err(e)) => {
            error!(
                ?e,
                purpose = purpose.label(),
                epoch,
                "delivered key conversion failed"
            );
            Response::Error {
                message: "delivered key conversion failed".to_string(),
            }
        }
        EpochKeyLookup::RootKeyAbsent => Response::RootKeyAbsent,
        EpochKeyLookup::Unavailable => Response::EpochKeyUnavailable { epoch },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{PURPOSE_KEY, ROOT_KEY, seal, state_with_root_key};
    use seismic_council_delivery::CouncilResponse;
    use seismic_custodian::Custodian;

    #[test]
    fn epoch_zero_and_ping_delegate_to_the_base_custodian() {
        let dir = tempfile::tempdir().unwrap();
        let state = state_with_root_key(dir.path());
        let custodian = Custodian::new(ROOT_KEY);

        let Response::TxIoKeypair(keys) = dispatch(&state, Request::GetTxIoKeypair { epoch: 0 })
        else {
            panic!("expected tx-io keypair");
        };
        assert_eq!(keys.sk, custodian.get_tx_io_sk(0).secret_bytes());

        let Response::RngIkm(rng) = dispatch(&state, Request::GetRngIkm { epoch: 0 }) else {
            panic!("expected rng ikm");
        };
        assert_eq!(rng.ikm, custodian.get_rng_ikm(0));

        assert!(matches!(dispatch(&state, Request::Ping), Response::Pong));
        // A bootstrap probe delegates too: the key is present.
        assert!(matches!(
            dispatch(&state, Request::CreateRootKeyBootstrapAttempt),
            Response::RootKeyAlreadyPresent
        ));
    }

    #[test]
    fn undelivered_epochs_answer_epoch_key_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let state = state_with_root_key(dir.path());
        for request in [
            Request::GetTxIoKeypair { epoch: 1 },
            Request::GetTxIoPublicKey { epoch: 1 },
            Request::GetRngIkm { epoch: 1 },
            Request::GetSnapshotKey { epoch: 2 },
        ] {
            let method = request.method();
            let response = dispatch(&state, request);
            assert!(
                matches!(response, Response::EpochKeyUnavailable { .. }),
                "{method} must answer EpochKeyUnavailable, got {}",
                response.kind()
            );
        }
    }

    #[test]
    fn delivered_epochs_serve_the_delivered_key() {
        let dir = tempfile::tempdir().unwrap();
        let state = state_with_root_key(dir.path());
        assert!(matches!(
            state.deliver(&seal(DeliveryPurpose::TxIo, 1, PURPOSE_KEY)),
            CouncilResponse::Delivered { .. }
        ));
        assert!(matches!(
            state.deliver(&seal(DeliveryPurpose::Snapshot, 1, [0xAB; 32])),
            CouncilResponse::Delivered { .. }
        ));

        // The delivered 32 bytes ARE the purpose key: the secret scalar for
        // tx-io, the AES key for snapshots.
        let Response::TxIoKeypair(keys) = dispatch(&state, Request::GetTxIoKeypair { epoch: 1 })
        else {
            panic!("expected tx-io keypair");
        };
        assert_eq!(keys.sk, PURPOSE_KEY);
        let expected_pk = secp256k1::PublicKey::from_secret_key(
            &secp256k1::Secp256k1::new(),
            &secp256k1::SecretKey::from_byte_array(&PURPOSE_KEY).unwrap(),
        );
        assert_eq!(keys.pk, expected_pk.serialize());

        let Response::TxIoPublicKey(pk) = dispatch(&state, Request::GetTxIoPublicKey { epoch: 1 })
        else {
            panic!("expected tx-io public key");
        };
        assert_eq!(pk.pk, expected_pk.serialize());

        let Response::SnapshotKey(snapshot) =
            dispatch(&state, Request::GetSnapshotKey { epoch: 1 })
        else {
            panic!("expected snapshot key");
        };
        assert_eq!(snapshot.key, [0xAB; 32]);

        // Epoch 0 still answers from derivation, unaffected by deliveries.
        let Response::TxIoKeypair(epoch0) = dispatch(&state, Request::GetTxIoKeypair { epoch: 0 })
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
        use crate::test_support::state_with_root_key;
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
            let state = Arc::new(state_with_root_key(dir.path()));

            let socket_path = dir.path().join("custodian.sock");
            let unix_listener = bind(&socket_path).expect("bind unix socket");
            let unix_state = state.clone();
            std::thread::spawn(move || {
                seismic_custodian_ipc::server::serve(
                    unix_listener,
                    MethodAcl::own_uid_only(),
                    move |request| dispatch(&unix_state, request),
                )
            });

            let tcp_listener =
                std::net::TcpListener::bind("127.0.0.1:0").expect("bind council port");
            let council_addr = tcp_listener.local_addr().expect("council addr");
            let council_state = state.clone();
            std::thread::spawn(move || serve_council(tcp_listener, council_state));

            // Before delivery: epoch 1 is a typed, retriable error.
            let mut client = CustodianClient::connect(&socket_path)
                .await
                .expect("connect");
            let error = client
                .get_tx_io_keypair(1)
                .await
                .expect_err("not delivered");
            assert!(matches!(error, IpcError::EpochKeyUnavailable { epoch: 1 }));

            // The council asks for status (inbox key, next epoch), delivers.
            let CouncilResponse::Status(status) =
                council_call(council_addr, &CouncilRequest::GetStatus)
            else {
                panic!("expected status");
            };
            assert!(status.accepting_deliveries);
            assert_eq!(status.tx_io_epoch, 0);
            let response = council_call(
                council_addr,
                &CouncilRequest::DeliverEpochKey(seal(DeliveryPurpose::TxIo, 1, PURPOSE_KEY)),
            );
            assert!(matches!(
                response,
                CouncilResponse::Delivered { epoch: 1, .. }
            ));

            // The delivered key now serves; epoch 0 still derives; epoch 2
            // stays unavailable.
            let keys = client.get_tx_io_keypair(1).await.expect("delivered epoch");
            assert_eq!(keys.sk, PURPOSE_KEY);
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
    }
}
