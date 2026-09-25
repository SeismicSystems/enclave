mod common;

use common::*;
use seismic_centralized_custodian_service::{council::CouncilHandler, observer::ParentFetcher};
use seismic_council_delivery::{
    CouncilRequest, CouncilResponse, MAX_ENVELOPES_PER_FETCH, ObserverQuery, ObserverRootKey,
    network_id_from_chain_id, observer_fetch_signing_payload,
};
use seismic_observer_key::{ObserverSigner, observer_namespace_from_chain_id, verify};
use std::{thread, time::Duration};
use tiny_http::{Header, Method, Request, Response, Server};

fn fetcher(base: String) -> ParentFetcher {
    ParentFetcher::new(
        &SEED,
        &observer_namespace_from_chain_id(CHAIN_ID),
        3,
        base,
        network_id_from_chain_id(CHAIN_ID),
    )
}

fn receive(server: &Server) -> (Request, CouncilRequest) {
    let mut request = server
        .recv_timeout(Duration::from_secs(5))
        .unwrap()
        .expect("observer did not issue HTTP request");
    assert_eq!(request.method(), &Method::Post);
    assert_eq!(request.url(), "/parent/custodian/v1/council");
    for name in ["Content-Type", "Accept"] {
        assert_eq!(
            request
                .headers()
                .iter()
                .find(|h| h.field.equiv(name))
                .unwrap()
                .value
                .as_str(),
            "application/cbor"
        );
    }
    let message = ciborium_decode(request.as_reader());
    (request, message)
}

// The service doesn't otherwise need a direct ciborium dependency. Decode via
// the shared strict codec, while independently checking the raw HTTP body.
fn ciborium_decode(mut reader: impl std::io::Read) -> CouncilRequest {
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    assert_ne!(bytes.first(), Some(&0), "old four-byte length prefix");
    seismic_council_delivery::http::decode(&bytes).unwrap()
}

fn reply(request: Request, response: CouncilResponse) {
    let bytes = seismic_council_delivery::http::encode(&response).unwrap();
    request
        .respond_and_close(
            Response::from_data(bytes.to_vec())
                .with_header(Header::from_bytes("Content-Type", "application/cbor").unwrap()),
        )
        .unwrap();
}

fn exchange(
    server: &Server,
    nonce: [u8; 32],
    expected_query: ObserverQuery,
    response: CouncilResponse,
) -> [std::net::SocketAddr; 2] {
    let (request, message) = receive(server);
    let challenge_peer = *request.remote_addr().unwrap();
    assert!(matches!(message, CouncilRequest::ObserverChallenge));
    reply(request, CouncilResponse::Challenge { nonce });
    // Check actual connections, not just the fixture's intended close header.
    let (http, message) = receive(server);
    let fetch_peer = *http.remote_addr().unwrap();
    assert_ne!(
        challenge_peer, fetch_peer,
        "fetch reused the challenge connection"
    );
    let CouncilRequest::ObserverFetch {
        nonce: received,
        request,
        signature,
    } = message
    else {
        panic!("expected signed fetch")
    };
    assert_eq!(received, nonce);
    assert_eq!(
        request.network_id,
        *network_id_from_chain_id(CHAIN_ID).as_bytes()
    );
    assert_eq!(request.observer_index, 3);
    assert_eq!(request.query, expected_query);
    let signer = ObserverSigner::derive(&SEED, &observer_namespace_from_chain_id(CHAIN_ID), 3);
    assert!(verify(
        &signer.public_key(),
        &observer_fetch_signing_payload(&nonce, &request).unwrap(),
        &signature
    ));
    reply(http, response);
    [challenge_peer, fetch_peer]
}

#[test]
fn caller_posts_signed_root_and_paginated_fetches_to_http_prefix() {
    let server = Server::http("127.0.0.1:0").unwrap();
    let base = format!("http://{}/parent/custodian", server.server_addr());
    let last = MAX_ENVELOPES_PER_FETCH as u64 + 1;
    let worker = thread::spawn(move || {
        let root_peers = exchange(
            &server,
            [1; 32],
            ObserverQuery::RootKey,
            CouncilResponse::RootKey(ObserverRootKey { key: ROOT }),
        );
        let first_page_peers = exchange(
            &server,
            [2; 32],
            ObserverQuery::Envelopes { from_epoch: 1 },
            CouncilResponse::Envelopes {
                envelopes: (1..last).map(envelope).collect(),
                delivered_epoch: last,
            },
        );
        let last_page_peers = exchange(
            &server,
            [3; 32],
            ObserverQuery::Envelopes { from_epoch: last },
            CouncilResponse::Envelopes {
                envelopes: vec![envelope(last)],
                delivered_epoch: last,
            },
        );
        let peers: std::collections::HashSet<_> = root_peers
            .into_iter()
            .chain(first_page_peers)
            .chain(last_page_peers)
            .collect();
        assert_eq!(
            peers.len(),
            6,
            "root/pagination exchanges must all reconnect"
        );
    });
    let caller = fetcher(base);
    assert_eq!(*caller.fetch_root_key().unwrap(), ROOT);
    let dir = tempfile::tempdir().unwrap();
    let observer = state(dir.path());
    caller.backfill(&observer).unwrap();
    assert_eq!(observer.status().epoch, last);
    assert_eq!(
        state(dir.path()).status().epoch,
        last,
        "fetched envelopes must be durable"
    );
    worker.join().unwrap();
}

#[test]
fn observer_handles_http_errors_and_malformed_responses_without_leaking_bodies() {
    for status in [200, 503, 307] {
        let server = Server::http("127.0.0.1:0").unwrap();
        let base = format!("http://{}/parent/custodian", server.server_addr());
        let worker = thread::spawn(move || {
            let (request, _) = receive(&server);
            request
                .respond(
                    Response::from_string("SECRET_MUST_NOT_APPEAR")
                        .with_status_code(status)
                        .with_header(
                            Header::from_bytes("Content-Type", "application/cbor").unwrap(),
                        ),
                )
                .unwrap();
        });
        let err = fetcher(base).fetch_root_key().unwrap_err();
        assert!(!format!("{err:#}").contains("SECRET_MUST_NOT_APPEAR"));
        worker.join().unwrap();
    }
}

#[test]
fn real_http_parent_serves_boot_backfill_and_on_demand_epochs() {
    let parent_dir = tempfile::tempdir().unwrap();
    let parent = state(parent_dir.path());
    parent.deliver(&envelope(1));
    let server = HttpServer::new(CouncilHandler::new(
        parent.clone(),
        Some(serving(parent_dir.path())),
    ));
    let caller = fetcher(server.base.clone());
    assert_eq!(*caller.fetch_root_key().unwrap(), ROOT);
    let observer_dir = tempfile::tempdir().unwrap();
    let observer = state(observer_dir.path());
    caller.backfill(&observer).unwrap();
    assert_eq!(observer.status().epoch, 1);
    parent.deliver(&envelope(2));
    assert!(caller.fetch_up_to(&observer, 2).unwrap());
    assert!(!caller.fetch_up_to(&observer, 3).unwrap());
}
