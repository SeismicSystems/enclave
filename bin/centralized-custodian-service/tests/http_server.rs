mod common;

use common::*;
use seismic_centralized_custodian_service::council::CouncilHandler;
use seismic_council_delivery::{
    CouncilRequest, CouncilResponse, RejectCode,
    http::{CouncilHttpClient, MAX_BODY_BYTES},
};
use std::{
    io::{Read, Write},
    net::TcpStream,
    time::Duration,
};

fn raw(
    base: &str,
    method: &str,
    path: &str,
    content_type: &str,
    body: &[u8],
    chunked: bool,
) -> Vec<u8> {
    let mut stream = TcpStream::connect(base.strip_prefix("http://").unwrap()).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let length = if chunked {
        "Transfer-Encoding: chunked\r\n".to_string()
    } else {
        format!("Content-Length: {}\r\n", body.len())
    };
    write!(stream, "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: {content_type}\r\n{length}\r\n").unwrap();
    if chunked {
        write!(stream, "{:x}\r\n", body.len()).unwrap();
    }
    stream.write_all(body).unwrap();
    if chunked {
        stream.write_all(b"\r\n0\r\n\r\n").unwrap();
    }
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    response
}

#[test]
fn enforces_http_contract_and_body_bounds() {
    let dir = tempfile::tempdir().unwrap();
    let server = HttpServer::new(CouncilHandler::new(state(dir.path()), None));
    let ping = seismic_council_delivery::http::encode(&CouncilRequest::Ping).unwrap();
    let mut framed = (ping.len() as u32).to_be_bytes().to_vec();
    framed.extend_from_slice(&ping);
    let oversized = vec![0; MAX_BODY_BYTES + 1];
    for (method, path, content_type, body, chunked, expected) in [
        (
            "POST",
            "/v1/council",
            "application/cbor",
            ping.as_slice(),
            false,
            200,
        ),
        (
            "GET",
            "/v1/council",
            "application/cbor",
            ping.as_slice(),
            false,
            405,
        ),
        (
            "POST",
            "/wrong",
            "application/cbor",
            ping.as_slice(),
            false,
            404,
        ),
        (
            "POST",
            "/v1/council?query=1",
            "application/cbor",
            ping.as_slice(),
            false,
            404,
        ),
        (
            "POST",
            "/v1/council",
            "application/json",
            ping.as_slice(),
            false,
            415,
        ),
        (
            "POST",
            "/v1/council",
            "application/cbor",
            b"not CBOR".as_slice(),
            false,
            400,
        ),
        (
            "POST",
            "/v1/council",
            "application/cbor",
            framed.as_slice(),
            false,
            400,
        ),
        (
            "POST",
            "/v1/council",
            "application/cbor",
            oversized.as_slice(),
            false,
            413,
        ),
        (
            "POST",
            "/v1/council",
            "application/cbor",
            oversized.as_slice(),
            true,
            413,
        ),
    ] {
        let wire = raw(&server.base, method, path, content_type, body, chunked);
        let headers = String::from_utf8_lossy(&wire);
        assert!(
            headers.starts_with(&format!("HTTP/1.1 {expected} ")),
            "{headers}"
        );
        assert!(
            headers
                .to_ascii_lowercase()
                .contains("cache-control: no-store")
        );
    }
}

#[test]
fn observer_nonce_works_across_clients_and_cannot_be_replayed() {
    use seismic_council_delivery::{
        ObserverFetchRequest, ObserverQuery, ObserverRejectCode, network_id_from_chain_id,
        observer_fetch_signing_payload,
    };
    use seismic_observer_key::{ObserverSigner, observer_namespace_from_chain_id};

    let dir = tempfile::tempdir().unwrap();
    let server = HttpServer::new(CouncilHandler::new(
        state(dir.path()),
        Some(serving(dir.path())),
    ));
    let issue = || {
        // A new agent for every call ensures separate HTTP connections.
        let response = CouncilHttpClient::new(&server.base)
            .unwrap()
            .call(&CouncilRequest::ObserverChallenge)
            .unwrap();
        let CouncilResponse::Challenge { nonce } = response else {
            panic!("expected challenge")
        };
        nonce
    };
    let first = issue();
    let second = issue();
    assert_ne!(first, second);
    let signer = ObserverSigner::derive(&SEED, &observer_namespace_from_chain_id(CHAIN_ID), 3);
    for nonce in [first, second] {
        let request = ObserverFetchRequest {
            network_id: *network_id_from_chain_id(CHAIN_ID).as_bytes(),
            observer_index: 3,
            query: ObserverQuery::RootKey,
        };
        let signature = signer.sign(&observer_fetch_signing_payload(&nonce, &request).unwrap());
        let fetch = CouncilRequest::ObserverFetch {
            nonce,
            request,
            signature,
        };
        let response = CouncilHttpClient::new(&server.base)
            .unwrap()
            .call(&fetch)
            .unwrap();
        assert!(matches!(response, CouncilResponse::RootKey(root) if root.key == ROOT));
        let replay = CouncilHttpClient::new(&server.base)
            .unwrap()
            .call(&fetch)
            .unwrap();
        assert!(matches!(
            replay,
            CouncilResponse::ObserverRejected {
                code: ObserverRejectCode::MissingChallenge,
                ..
            }
        ));
    }
}

#[test]
fn real_http_delivery_preserves_verification_conflicts_and_persistence() {
    let dir = tempfile::tempdir().unwrap();
    let state = state(dir.path());
    let server = HttpServer::new(CouncilHandler::new(state.clone(), None));
    let client = CouncilHttpClient::new(&server.base).unwrap();
    let delivery = envelope(1);
    let mut invalid = delivery.clone();
    invalid.signature = [0; 65];
    assert!(matches!(
        client
            .call(&CouncilRequest::DeliverEpochKey(invalid))
            .unwrap(),
        CouncilResponse::Rejected {
            code: RejectCode::BadSignature,
            ..
        }
    ));
    let mut wrong_network = delivery.clone();
    wrong_network.payload.network_id = [0; 32];
    assert!(matches!(
        client
            .call(&CouncilRequest::DeliverEpochKey(wrong_network))
            .unwrap(),
        CouncilResponse::Rejected {
            code: RejectCode::WrongNetwork,
            ..
        }
    ));
    assert!(matches!(
        client
            .call(&CouncilRequest::DeliverEpochKey(envelope(2)))
            .unwrap(),
        CouncilResponse::Rejected {
            code: RejectCode::NonSequentialEpoch,
            ..
        }
    ));
    assert!(matches!(
        client
            .call(&CouncilRequest::DeliverEpochKey(delivery.clone()))
            .unwrap(),
        CouncilResponse::Delivered { epoch: 1 }
    ));
    assert!(matches!(
        client
            .call(&CouncilRequest::DeliverEpochKey(delivery))
            .unwrap(),
        CouncilResponse::AlreadyDelivered { epoch: 1 }
    ));
    let conflicting = seismic_council_delivery::seal_delivery(
        &council_key(),
        &seismic_council_delivery::network_id_from_chain_id(CHAIN_ID),
        1,
        &[0x55; 32],
    );
    assert!(matches!(
        client
            .call(&CouncilRequest::DeliverEpochKey(conflicting))
            .unwrap(),
        CouncilResponse::Rejected {
            code: RejectCode::EpochConflict,
            ..
        }
    ));
    assert_eq!(common::state(dir.path()).status().epoch, 1);
}
