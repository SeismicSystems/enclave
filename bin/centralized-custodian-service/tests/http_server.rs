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
    // Metrics are process-global and other tests in this binary also drive
    // the handler, so the checks below assert presence and lower bounds.
    seismic_centralized_custodian_service::metrics::init("validator");
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

    // The same listener serves Prometheus metrics. After the deliveries
    // above: the epoch gauge advanced on the one accepted delivery, every
    // council outcome seen is counted, and the exposition is well formed.
    let scrape = raw(&server.base, "GET", "/metrics", "text/plain", b"", false);
    let scrape = String::from_utf8(scrape).unwrap();
    let (headers, body) = scrape.split_once("\r\n\r\n").unwrap();
    assert!(headers.starts_with("HTTP/1.1 200"), "{headers}");
    assert!(
        headers.contains("Content-Type: text/plain; version=0.0.4; charset=utf-8"),
        "{headers}"
    );
    assert!(headers.contains("Cache-Control: no-store"), "{headers}");
    let counter = |body: &str, series: &str| -> u64 {
        body.lines()
            .find_map(|l| l.strip_prefix(series).and_then(|v| v.trim().parse().ok()))
            .unwrap_or_else(|| panic!("missing series {series}: {body}"))
    };
    assert_eq!(counter(body, "custodian_delivered_epoch"), 1, "{body}");
    assert!(
        counter(
            body,
            "custodian_council_requests_total{outcome=\"delivered\"}"
        ) >= 1
    );
    assert!(
        counter(
            body,
            "custodian_council_requests_total{outcome=\"already_delivered\"}"
        ) >= 1
    );
    assert!(
        counter(
            body,
            "custodian_council_requests_total{outcome=\"rejected\"}"
        ) >= 4
    );
    assert!(
        body.contains("custodian_build_info{") && body.contains("role=\"validator\""),
        "{body}"
    );
    // No payloads, nonces, or key bytes leak into the scrape.
    assert!(!body.contains("0x") && !body.contains("55555555"), "{body}");
    for line in body.lines() {
        assert!(
            line.is_empty()
                || line.starts_with('#')
                || line
                    .rsplit_once(' ')
                    .is_some_and(|(_, v)| v.parse::<f64>().is_ok()),
            "malformed exposition line: {line:?}"
        );
    }
    // A non-GET on /metrics is not a metrics request; it falls through to
    // the council path's 404 and is counted as an HTTP error.
    let before = counter(body, "custodian_council_http_errors_total{status=\"404\"}");
    let bad = raw(
        &server.base,
        "POST",
        "/metrics",
        "application/cbor",
        b"",
        false,
    );
    assert!(String::from_utf8_lossy(&bad).starts_with("HTTP/1.1 404"));
    let scrape = String::from_utf8(raw(
        &server.base,
        "GET",
        "/metrics",
        "text/plain",
        b"",
        false,
    ))
    .unwrap();
    assert_eq!(
        counter(
            &scrape,
            "custodian_council_http_errors_total{status=\"404\"}"
        ),
        before + 1,
        "{scrape}"
    );
}
