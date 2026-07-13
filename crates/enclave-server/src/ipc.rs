//! Dispatch for the custodian Unix socket: the shim between the wire
//! protocol and [`Custodian`].
//!
//! The transport — bind semantics, peer credentials, ACL-before-dispatch,
//! the frame loop — lives in `seismic_custodian_ipc::server` and is shared
//! with any future host. This module is only the part that must live next to
//! the key: mapping authorized [`Request`]s onto custodian operations.

use anyhow::Context as _;
use seismic_custodian_ipc::{
    Request, Response, RngKeypairBytes, SnapshotKeyBytes, TxIoKeypairBytes, WrappedRootKeyBytes,
};
use seismic_key_custodian::{Custodian, VerifiedPeerAuthorization};

/// Map one ACL-authorized socket request onto the custodian.
///
/// No production caller connects to the socket yet — reth still fetches keys
/// over HTTP `getPurposeKeys`, and the bootstrap responder calls `Custodian`
/// directly in-process — so today only tests and the debug CLI land here.
/// See the wiring note in `server::start_server`.
pub fn dispatch(custodian: &Custodian, request: Request) -> Response {
    match request {
        Request::Ping => Response::Pong,
        Request::GetTxIoKeypair { epoch } => Response::TxIoKeypair(TxIoKeypairBytes {
            sk: custodian.get_tx_io_sk(epoch).secret_bytes(),
            pk: custodian.get_tx_io_pk(epoch).serialize(),
        }),
        Request::GetRngKeypair { epoch } => Response::RngKeypair(RngKeypairBytes {
            keypair: custodian.get_rng_keypair(epoch).to_bytes().to_vec(),
        }),
        Request::GetSnapshotKey { epoch } => Response::SnapshotKey(SnapshotKeyBytes {
            key: custodian.get_snapshot_key(epoch).into(),
        }),
        Request::WrapRootKey {
            root_key_request_binding,
            peer_eph_pk,
        } => match wrap_root_key(custodian, root_key_request_binding, &peer_eph_pk) {
            Ok(wrapped) => Response::WrappedRootKey(wrapped),
            Err(e) => Response::Error {
                message: format!("wrap_root_key: {e:#}"),
            },
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
    use seismic_key_custodian::{EphemeralKeypair, unwrap_root_key};

    const ROOT_KEY: [u8; 32] = [7u8; 32];

    #[test]
    fn ping_pong() {
        let custodian = Custodian::new(ROOT_KEY);
        assert!(matches!(
            dispatch(&custodian, Request::Ping),
            Response::Pong
        ));
    }

    #[test]
    fn purpose_keys_match_direct_derivation() {
        let custodian = Custodian::new(ROOT_KEY);

        // Parity with the JSON-RPC get_purpose_keys handler: both surfaces
        // serve the same Custodian getters.
        let Response::TxIoKeypair(tx_io) =
            dispatch(&custodian, Request::GetTxIoKeypair { epoch: 0 })
        else {
            panic!("expected tx-io keypair");
        };
        assert_eq!(tx_io.sk, custodian.get_tx_io_sk(0).secret_bytes());
        assert_eq!(tx_io.pk, custodian.get_tx_io_pk(0).serialize());

        let Response::RngKeypair(rng) = dispatch(&custodian, Request::GetRngKeypair { epoch: 0 })
        else {
            panic!("expected rng keypair");
        };
        assert_eq!(
            rng.keypair,
            custodian.get_rng_keypair(0).to_bytes().to_vec()
        );

        let Response::SnapshotKey(snapshot) =
            dispatch(&custodian, Request::GetSnapshotKey { epoch: 0 })
        else {
            panic!("expected snapshot key");
        };
        let expected: [u8; 32] = custodian.get_snapshot_key(0).into();
        assert_eq!(snapshot.key, expected);

        let Response::TxIoKeypair(tx_io_epoch1) =
            dispatch(&custodian, Request::GetTxIoKeypair { epoch: 1 })
        else {
            panic!("expected tx-io keypair");
        };
        assert_ne!(tx_io.sk, tx_io_epoch1.sk, "epochs must differ");
    }

    #[test]
    fn wrap_root_key_roundtrips_through_unwrap() {
        let custodian = Custodian::new(ROOT_KEY);
        let eph = EphemeralKeypair::generate();
        let binding = [0x33u8; 32];
        let Response::WrappedRootKey(wrapped) = dispatch(
            &custodian,
            Request::WrapRootKey {
                root_key_request_binding: binding,
                peer_eph_pk: eph.pk_compressed(),
            },
        ) else {
            panic!("expected wrapped root key");
        };

        let responder_pk =
            secp256k1::PublicKey::from_slice(&wrapped.responder_eph_pk).expect("responder pk");
        let recovered =
            unwrap_root_key(&eph.sk, &responder_pk, &wrapped.wrapped, &binding).expect("unwrap");
        assert_eq!(recovered, ROOT_KEY);
    }

    #[test]
    fn wrap_root_key_rejects_invalid_peer_point() {
        let custodian = Custodian::new(ROOT_KEY);
        let response = dispatch(
            &custodian,
            Request::WrapRootKey {
                root_key_request_binding: [0u8; 32],
                peer_eph_pk: [0u8; 33],
            },
        );
        assert!(matches!(response, Response::Error { .. }));
    }

    /// Coverage over a real `UnixListener`: bind semantics, `SO_PEERCRED`
    /// attribution, and the crate server + async client end-to-end. Needs an
    /// environment permitting `AF_UNIX` bind (CI, a dev machine); in a
    /// sandbox that forbids it, skip with `-- --skip real_socket`.
    mod real_socket {
        use super::*;
        use seismic_custodian_ipc::CustodianClient;
        use seismic_custodian_ipc::server::{MethodAcl, bind, serve};
        use std::os::unix::fs::PermissionsExt as _;
        use std::sync::Arc;

        #[test]
        fn bind_sets_permissions_and_replaces_stale_socket() {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("custodian.sock");

            // Bind, then bind again without unlinking: the stale inode from
            // the "previous run" must be replaced, not fail the restart.
            let stale = bind(&path).expect("first bind");
            drop(stale);
            let listener = bind(&path).expect("rebind over stale socket");
            drop(listener);

            let mode = std::fs::metadata(&path)
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o660, "socket must be 0660");
        }

        #[tokio::test]
        async fn own_uid_is_authorized_via_peer_cred() {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("custodian.sock");
            let listener = bind(&path).expect("bind");
            let custodian = Arc::new(Custodian::new(ROOT_KEY));
            std::thread::spawn(move || {
                serve(listener, MethodAcl::own_uid_only(), move |request| {
                    dispatch(&custodian, request)
                })
            });

            // The test process connects as itself, so the kernel reports our
            // own UID and the own-uid-only ACL must authorize key methods.
            let mut client = CustodianClient::connect(&path).await.expect("connect");
            client.ping().await.expect("ping");
            let keys = client.get_tx_io_keypair(0).await.expect("tx-io keypair");
            let custodian = Custodian::new(ROOT_KEY);
            assert_eq!(keys.sk, custodian.get_tx_io_sk(0).secret_bytes());
        }
    }
}
