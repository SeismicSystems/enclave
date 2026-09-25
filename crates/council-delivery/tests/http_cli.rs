#![cfg(feature = "cli")]
//! Exercise the real CLI process against HTTP fixtures, not just its URL parser.

use seismic_council_delivery::{
    CouncilRequest, CouncilResponse, CouncilStatus, canonical_envelope_bytes,
    network_id_from_chain_id, seal_delivery, verify_delivery,
};
use std::{
    path::Path,
    process::{Command, Output},
    thread,
    time::Duration,
};
use tiny_http::{Header, Method, Request, Response, Server};

fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_council-signer"));
    for key in [
        "COUNCIL_ROOT_KEY",
        "COUNCIL_SIGNER_KEY",
        "COUNCIL_ENVELOPE_DIR",
        "SEISMIC_CHAIN_ID",
    ] {
        command.env_remove(key);
    }
    command
}

fn assert_success(output: Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn server() -> (Server, String) {
    let server = Server::http("127.0.0.1:0").unwrap();
    let base = format!("http://{}/custodian", server.server_addr());
    (server, base)
}

fn receive(server: &Server) -> (Request, CouncilRequest) {
    let mut request = server
        .recv_timeout(Duration::from_secs(10))
        .unwrap()
        .expect("CLI did not call HTTP endpoint");
    assert_eq!(request.method(), &Method::Post);
    assert_eq!(request.url(), "/custodian/v1/council");
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
    // Independently decode the HTTP body. An old four-byte frame prefix fails.
    let message = ciborium::from_reader(request.as_reader()).expect("unframed CBOR request");
    (request, message)
}

fn reply(request: Request, message: CouncilResponse) {
    let mut bytes = Vec::new();
    ciborium::into_writer(&message, &mut bytes).unwrap();
    request
        // Unlike with_header("Connection", "close"), this API closes the socket.
        .respond_and_close(
            Response::from_data(bytes)
                .with_header(Header::from_bytes("Content-Type", "application/cbor").unwrap()),
        )
        .unwrap();
}

fn status(epoch: u64) -> CouncilResponse {
    CouncilResponse::Status(CouncilStatus {
        network_id: *network_id_from_chain_id(5124).as_bytes(),
        epoch,
    })
}

fn fixture_envelope(epoch: u64) -> seismic_council_delivery::SignedDeliveryEnvelope {
    seal_delivery(
        &secp256k1::SecretKey::from_byte_array(&[0x77; 32]).unwrap(),
        &network_id_from_chain_id(5124),
        epoch,
        &[0x42; 32],
    )
}

#[test]
fn status_and_signed_delivery_use_http_and_save_the_same_envelope() {
    let (server, base) = server();
    let worker = thread::spawn(move || {
        let (request, message) = receive(&server);
        assert!(matches!(message, CouncilRequest::GetStatus));
        reply(request, status(0));
        let (request, message) = receive(&server);
        let CouncilRequest::DeliverEpochKey(envelope) = message else {
            panic!("expected delivery")
        };
        let expected = fixture_envelope(1);
        assert_eq!(envelope, expected);
        let public = secp256k1::SecretKey::from_byte_array(&[0x77; 32])
            .unwrap()
            .public_key(&secp256k1::Secp256k1::new());
        let address = seismic_council_delivery::address_from_pubkey(&public);
        verify_delivery(&envelope, &address, &network_id_from_chain_id(5124)).unwrap();
        reply(request, CouncilResponse::Delivered { epoch: 1 });
    });
    let output = command()
        .args(["status", "--node", &base])
        .output()
        .unwrap();
    assert!(assert_success(output).contains("next delivery: 1"));

    let dir = tempfile::tempdir().unwrap();
    let signature = format!("0x{}", hex::encode(fixture_envelope(1).signature));
    let output = command()
        .args([
            "deliver",
            "--node",
            &base,
            "--chain-id",
            "5124",
            "--epoch",
            "1",
            "--signature",
            &signature,
            "--save-dir",
        ])
        .arg(dir.path())
        .env("COUNCIL_ROOT_KEY", format!("0x{}", hex::encode([0x42; 32])))
        .output()
        .unwrap();
    assert!(assert_success(output).contains("delivered root key for epoch 1"));
    assert_eq!(
        std::fs::read(dir.path().join("1.cbor")).unwrap(),
        *canonical_envelope_bytes(&fixture_envelope(1)).unwrap()
    );
    worker.join().unwrap();
}

fn write_envelopes(dir: &Path) {
    for epoch in 1..=3 {
        std::fs::write(
            dir.join(format!("{epoch}.cbor")),
            &*canonical_envelope_bytes(&fixture_envelope(epoch)).unwrap(),
        )
        .unwrap();
    }
}

#[test]
fn batch_uses_status_then_posts_only_missing_epochs_across_connections() {
    let (server, base) = server();
    let worker = thread::spawn(move || {
        let (request, message) = receive(&server);
        assert!(matches!(message, CouncilRequest::GetStatus));
        let mut peers = std::collections::HashSet::new();
        peers.insert(*request.remote_addr().unwrap());
        reply(request, status(1));
        for epoch in 2..=3 {
            let (request, message) = receive(&server);
            assert!(
                peers.insert(*request.remote_addr().unwrap()),
                "batch reused a connection instead of reconnecting"
            );
            let CouncilRequest::DeliverEpochKey(envelope) = message else {
                panic!("expected delivery")
            };
            assert_eq!(envelope, fixture_envelope(epoch));
            reply(request, CouncilResponse::Delivered { epoch });
        }
    });
    let dir = tempfile::tempdir().unwrap();
    write_envelopes(dir.path());
    let output = command()
        .args(["deliver-batch", "--node", &base, "--envelope-dir"])
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(assert_success(output).contains("now at epoch 3"));
    worker.join().unwrap();
}

#[test]
fn fleet_continues_after_http_failure_and_reports_nonzero() {
    let (bad, bad_url) = server();
    let (good, good_url) = server();
    let worker = thread::spawn(move || {
        let (request, _) = receive(&bad);
        request
            .respond(
                Response::from_string("SECRET_RESPONSE_MUST_NOT_BE_LOGGED").with_status_code(503),
            )
            .unwrap();
        let (request, message) = receive(&good);
        assert!(matches!(message, CouncilRequest::GetStatus));
        reply(request, status(2));
    });
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fleet.toml");
    std::fs::write(&path, format!("nodes = [{bad_url:?}, {good_url:?}]\n")).unwrap();
    let output = command()
        .args(["status", "--nodes-file"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("503"));
    assert!(!stderr.contains("SECRET_RESPONSE"));
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("next delivery: 3")
    );
    worker.join().unwrap();
}

#[test]
fn invalid_fleet_url_fails_before_any_network_request() {
    let (server, base) = server();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fleet.toml");
    std::fs::write(&path, format!("nodes = [{base:?}, \"tls://legacy:7443\"]")).unwrap();
    let output = command()
        .args(["status", "--nodes-file"])
        .arg(path)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        server
            .recv_timeout(Duration::from_millis(100))
            .unwrap()
            .is_none()
    );
}
