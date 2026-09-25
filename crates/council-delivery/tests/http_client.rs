#![cfg(feature = "http-client")]

use seismic_council_delivery::{
    CouncilRequest,
    http::{CouncilHttpClient, MAX_BODY_BYTES},
};
use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
    time::Duration,
};

/// A raw HTTP fixture gives us complete control of malformed headers/bodies.
fn fixture(response: Vec<u8>, delay: Duration) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let worker = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut headers = Vec::new();
        while !headers.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            stream.read_exact(&mut byte).unwrap();
            headers.push(byte[0]);
            assert!(headers.len() < 8192);
        }
        assert!(headers.starts_with(b"POST /v1/council HTTP/1.1\r\n"));
        let text = String::from_utf8(headers).unwrap().to_ascii_lowercase();
        let length: usize = text
            .lines()
            .find_map(|line| line.strip_prefix("content-length:"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let mut body = vec![0; length];
        stream.read_exact(&mut body).unwrap();
        let message: CouncilRequest = ciborium::from_reader(body.as_slice()).unwrap();
        assert!(matches!(message, CouncilRequest::Ping));
        thread::sleep(delay);
        let _ = stream.write_all(&response);
    });
    (base, worker)
}

fn response(status: &str, headers: &str, body: &[u8]) -> Vec<u8> {
    let mut bytes = format!(
        "HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: {}\r\n{headers}\r\n",
        body.len()
    )
    .into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

#[test]
fn rejects_bad_status_content_type_malformed_trailing_and_oversize_bodies() {
    let cases = [
        response("503 Unavailable", "", b"SECRET_DO_NOT_LOG"),
        response("200 OK", "Content-Type: application/json\r\n", b"{}"),
        response(
            "200 OK",
            "Content-Type: application/cbor\r\n",
            b"SECRET_DO_NOT_LOG",
        ),
        response(
            "200 OK",
            "Content-Type: application/cbor\r\n",
            b"\x64Pong\x00",
        ),
        response(
            "200 OK",
            "Content-Type: application/cbor\r\n",
            &vec![0; MAX_BODY_BYTES + 1],
        ),
    ];
    for wire in cases {
        let (base, worker) = fixture(wire, Duration::ZERO);
        let error = CouncilHttpClient::new(&base)
            .unwrap()
            .call(&CouncilRequest::Ping)
            .unwrap_err();
        assert!(!format!("{error:#}").contains("SECRET_DO_NOT_LOG"));
        worker.join().unwrap();
    }
}

#[test]
fn chunked_response_is_bounded_without_content_length() {
    let chunk = vec![b'x'; MAX_BODY_BYTES + 1];
    let mut wire = b"HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_vec();
    wire.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
    wire.extend_from_slice(&chunk);
    wire.extend_from_slice(b"\r\n0\r\n\r\n");
    let (base, worker) = fixture(wire, Duration::ZERO);
    let error = CouncilHttpClient::new(&base)
        .unwrap()
        .call(&CouncilRequest::Ping)
        .unwrap_err();
    assert!(format!("{error:#}").contains("exceeds 64 KiB"));
    worker.join().unwrap();
}

#[test]
fn redirects_are_never_followed() {
    let target = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let headers = format!("Location: http://{}/leak\r\n", target.server_addr());
    let (base, worker) = fixture(
        response("307 Temporary Redirect", &headers, b""),
        Duration::ZERO,
    );
    let error = CouncilHttpClient::new(&base)
        .unwrap()
        .call(&CouncilRequest::Ping)
        .unwrap_err();
    assert!(error.to_string().contains("307"));
    worker.join().unwrap();
    assert!(
        target
            .recv_timeout(Duration::from_millis(100))
            .unwrap()
            .is_none()
    );
}

#[test]
fn https_rejects_untrusted_certificates_before_sending_a_delivery() {
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::sync::Arc;

    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![certified.cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                certified.signing_key.serialize_der(),
            )),
        )
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!(
        "https://localhost:{}",
        listener.local_addr().unwrap().port()
    );
    let worker = thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let connection = rustls::ServerConnection::new(Arc::new(config)).unwrap();
        let mut tls = rustls::StreamOwned::new(connection, tcp);
        // Certificate rejection must occur before any HTTP body or header arrives.
        let mut byte = [0];
        assert!(tls.read(&mut byte).is_err());
    });
    let envelope = seismic_council_delivery::seal_delivery(
        &secp256k1::SecretKey::from_byte_array(&[0x77; 32]).unwrap(),
        &seismic_council_delivery::network_id_from_chain_id(5124),
        1,
        &[0x42; 32],
    );
    let error = CouncilHttpClient::new(&base)
        .unwrap()
        .call(&CouncilRequest::DeliverEpochKey(envelope))
        .unwrap_err();
    assert!(format!("{error:#}").contains("UnknownIssuer"), "{error:#}");
    worker.join().unwrap();
}

#[test]
fn requests_have_a_deadline() {
    let (base, worker) = fixture(
        response("200 OK", "Content-Type: application/cbor\r\n", b"\x64Pong"),
        Duration::from_millis(400),
    );
    let client = CouncilHttpClient::with_timeout(&base, Duration::from_millis(100)).unwrap();
    assert!(client.call(&CouncilRequest::Ping).is_err());
    worker.join().unwrap();
}
