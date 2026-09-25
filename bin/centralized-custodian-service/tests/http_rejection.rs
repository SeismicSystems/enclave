//! Rejection cleanup is part of the security boundary, not just the HTTP status.
//! Exercise the shipped binary in a memory-limited subprocess so a regression
//! cannot OOM the test runner or leave the entire test suite blocked in Drop.
#![cfg(target_os = "linux")]

use seismic_council_delivery::{
    CouncilRequest, CouncilResponse, address_from_pubkey,
    http::{CouncilHttpClient, MAX_BODY_BYTES, decode, encode},
    network_id_from_chain_id, seal_delivery,
};
use std::{
    io::{Read, Write},
    net::{Shutdown, TcpStream},
    os::unix::{net::UnixStream, process::CommandExt},
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const IO_TIMEOUT: Duration = Duration::from_secs(3);

fn council_key() -> secp256k1::SecretKey {
    secp256k1::SecretKey::from_byte_array(&[0x77; 32]).unwrap()
}

struct CustodianProcess {
    child: Child,
    dir: tempfile::TempDir,
    base: String,
}

impl CustodianProcess {
    fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let log = std::fs::File::create(dir.path().join("service.log")).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_seismic-centralized-custodian-service"));
        command
            .env_clear()
            .env("RUST_LOG", "info")
            .args(["--council-listen", "127.0.0.1:0", "--chain-id", "5124"])
            .arg("--council-address")
            .arg(format!(
                "0x{}",
                hex::encode(address_from_pubkey(
                    &council_key().public_key(&secp256k1::Secp256k1::new())
                ))
            ))
            .arg("--socket")
            .arg(dir.path().join("custodian.sock"))
            .arg("--root-key-file")
            .arg(dir.path().join("root.key"))
            .arg("--delivery-dir")
            .arg(dir.path().join("deliveries"))
            .stdin(Stdio::null())
            .stderr(log.try_clone().unwrap())
            .stdout(log);
        // SAFETY: only async-signal-safe setrlimit calls are made between fork
        // and exec. Limits apply only to the disposable child, never the runner.
        unsafe {
            command.pre_exec(|| {
                for (resource, limit) in
                    [(libc::RLIMIT_AS, 512 * 1024 * 1024), (libc::RLIMIT_CORE, 0)]
                {
                    let limit = libc::rlimit {
                        rlim_cur: limit,
                        rlim_max: limit,
                    };
                    if libc::setrlimit(resource, &limit) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        let mut process = Self {
            child: command.spawn().unwrap(),
            dir,
            base: String::new(),
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            assert!(
                process.child.try_wait().unwrap().is_none(),
                "{}",
                process.log()
            );
            // Ask the OS to choose the port; don't race by reserving and releasing
            // a port in the parent. The listener reports its actual bound address.
            if let Some(line) = process
                .log()
                .lines()
                .find(|line| line.contains("council HTTP endpoint listening"))
                && let Some((_, tail)) = line.split_once("127.0.0.1:")
            {
                let port: String = tail.chars().take_while(char::is_ascii_digit).collect();
                assert!(!port.is_empty(), "missing port in {line}");
                process.base = format!("http://127.0.0.1:{port}");
                break;
            }
            assert!(
                Instant::now() < deadline,
                "startup timed out: {}",
                process.log()
            );
            thread::sleep(Duration::from_millis(10));
        }
        process.assert_healthy();
        process
    }

    fn resources(&self) -> (usize, usize) {
        let proc = PathBuf::from(format!("/proc/{}", self.child.id()));
        let count = |name| std::fs::read_dir(proc.join(name)).unwrap().count();
        (count("task"), count("fd"))
    }

    fn socket_path(&self) -> PathBuf {
        self.dir.path().join("custodian.sock")
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("service.log")).unwrap()
    }

    fn connect(&self) -> TcpStream {
        let stream = TcpStream::connect(self.base.strip_prefix("http://").unwrap()).unwrap();
        stream.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
        stream.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
        stream
    }

    fn assert_healthy(&mut self) {
        assert!(self.child.try_wait().unwrap().is_none(), "{}", self.log());
        assert!(matches!(
            CouncilHttpClient::with_timeout(&self.base, IO_TIMEOUT)
                .unwrap()
                .call(&CouncilRequest::Ping)
                .unwrap(),
            CouncilResponse::Pong
        ));
        // A process-wide abort would also take down Reth's unrelated IPC API.
        let mut ipc = UnixStream::connect(self.socket_path()).unwrap();
        ipc.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
        ipc.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
        seismic_custodian_ipc::write_frame_blocking(
            &mut ipc,
            &seismic_custodian_ipc::Request::Ping,
        )
        .unwrap();
        assert!(matches!(
            seismic_custodian_ipc::read_frame_blocking(&mut ipc).unwrap(),
            Some(seismic_custodian_ipc::Response::Pong)
        ));
    }
}

impl Drop for CustodianProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn assert_final_response_and_eof(stream: &mut TcpStream, status: u16) {
    let mut response = Vec::new();
    // A response status alone is not enough: cleanup must finish without waiting
    // for the withheld request body or for the client to close its write side.
    stream.read_to_end(&mut response).unwrap();
    let header_end = response.windows(4).position(|b| b == b"\r\n\r\n").unwrap() + 4;
    let text = std::str::from_utf8(&response[..header_end]).unwrap();
    assert!(text.starts_with(&format!("HTTP/1.1 {status} ")), "{text}");
    assert!(
        text.to_ascii_lowercase()
            .contains("\r\nconnection: close\r\n"),
        "{text}"
    );
    assert_eq!(
        response
            .windows(b"HTTP/1.1 ".len())
            .filter(|bytes| *bytes == b"HTTP/1.1 ")
            .count(),
        1,
        "unexpected extra response: {text}"
    );
}

#[test]
fn unsupported_versions_close_without_retaining_parser_resources() {
    let mut process = CustodianProcess::start();
    let baseline = process.resources();
    for index in 0..32 {
        let version = if index % 2 == 0 { "2.0" } else { "3.0" };
        let mut stream = process.connect();
        // No body: rejection must precede request construction, including its
        // eager buffering of small bodies. Alternate with an empty body request
        // to cover the original circular sequential-writer wait directly.
        let length = if index % 4 < 2 { 0 } else { 5 };
        // Send in one write: the server can reject as soon as it sees the
        // request line, before a fragmented formatting write sends headers.
        stream.write_all(format!("POST /v1/council HTTP/{version}\r\nHost: localhost\r\nContent-Length: {length}\r\n\r\n").as_bytes()).unwrap();
        assert_final_response_and_eof(&mut stream, 505);
    }
    process.assert_healthy();
    // Extra idle parser threads expire after five seconds. Peer EOF alone must
    // also release every per-connection socket handle; allow scheduler slack.
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        let current = process.resources();
        if current.0 <= baseline.0 && current.1 <= baseline.1 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "parser resources retained: baseline {baseline:?}, current {current:?}"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

fn truncated_delivery_is_not_dispatched(chunked: bool, upgrade: bool) {
    let mut process = CustodianProcess::start();
    let delivery = CouncilRequest::DeliverEpochKey(seal_delivery(
        &council_key(),
        &network_id_from_chain_id(5124),
        1,
        &[0x42; 32],
    ));
    let body = encode(&delivery).unwrap();
    assert!(body.len() < 2048);
    let framing = if chunked {
        "Transfer-Encoding: chunked\r\n\r\n800\r\n"
    } else {
        "Content-Length: 2048\r\n\r\n"
    };
    let connection = if upgrade {
        "Connection: upgrade\r\n"
    } else {
        ""
    };
    let mut wire = format!("POST /v1/council HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/cbor\r\n{connection}{framing}").into_bytes();
    wire.extend_from_slice(&body);
    let mut stream = process.connect();
    stream.write_all(&wire).unwrap();
    stream.shutdown(Shutdown::Write).unwrap();
    assert_final_response_and_eof(&mut stream, if upgrade { 400 } else { 413 });
    assert!(!process.log().contains("deliver_epoch_key"));
    let client = CouncilHttpClient::with_timeout(&process.base, IO_TIMEOUT).unwrap();
    assert!(matches!(
        client.call(&CouncilRequest::GetStatus).unwrap(),
        CouncilResponse::Status(status) if status.epoch == 0
    ));
    assert_eq!(
        std::fs::read_dir(process.dir.path().join("deliveries"))
            .unwrap()
            .count(),
        0,
        "truncated delivery persisted an envelope"
    );
    process.assert_healthy();

    // Positive control: the identical signature/key must be accepted when the
    // framing is complete. Exercise both fixed-length and chunked success.
    let framing = if chunked {
        format!("Transfer-Encoding: chunked\r\n\r\n{:x}\r\n", body.len())
    } else {
        format!("Content-Length: {}\r\n\r\n", body.len())
    };
    let mut stream = process.connect();
    write!(stream, "POST /v1/council HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/cbor\r\nConnection: close\r\n{framing}").unwrap();
    stream.write_all(&body).unwrap();
    if chunked {
        stream.write_all(b"\r\n0\r\n\r\n").unwrap();
    }
    stream.shutdown(Shutdown::Write).unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200 "));
    let body_start = response.windows(4).position(|b| b == b"\r\n\r\n").unwrap() + 4;
    assert!(matches!(
        decode::<CouncilResponse>(&response[body_start..]).unwrap(),
        CouncilResponse::Delivered { epoch: 1 }
    ));
    assert!(process.dir.path().join("deliveries/1.cbor").is_file());
    assert!(matches!(
        client.call(&CouncilRequest::GetStatus).unwrap(),
        CouncilResponse::Status(status) if status.epoch == 1
    ));
    process.assert_healthy();
}

#[test]
fn truncated_fixed_length_delivery_is_not_dispatched() {
    truncated_delivery_is_not_dispatched(false, false);
}

#[test]
fn truncated_chunked_delivery_is_not_dispatched() {
    truncated_delivery_is_not_dispatched(true, false);
}

#[test]
fn upgrade_cannot_bypass_delivery_body_framing() {
    truncated_delivery_is_not_dispatched(false, true);
}

#[test]
fn oversized_and_early_rejected_bodies_close_without_allocation_or_draining() {
    let mut process = CustodianProcess::start();
    let mut clients = Vec::new();
    // More than the entire 16-worker pool; leave client write sides open. Even
    // bounded draining would exhaust the pool if rejection did not cancel it.
    for index in 0..32 {
        let (method, path, content_type, length, status) = match index % 5 {
            0 => ("POST", "/v1/council", "application/cbor", 1u64 << 30, 413),
            1 => ("POST", "/v1/council", "application/cbor", u64::MAX, 413),
            2 => ("POST", "/wrong", "application/cbor", 2048, 404),
            3 => ("GET", "/v1/council", "application/cbor", 1u64 << 30, 405),
            _ => ("POST", "/v1/council", "application/json", 1u64 << 30, 415),
        };
        let mut stream = process.connect();
        write!(stream, "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: {content_type}\r\nContent-Length: {length}\r\nExpect: 100-continue\r\nConnection: keep-alive\r\n\r\n").unwrap();
        // Send headers only. In particular, do not fulfill Content-Length.
        assert_final_response_and_eof(&mut stream, status);
        clients.push(stream);
        process.assert_healthy();
    }
}

#[test]
fn unfinished_chunked_body_is_cancelled_and_cannot_become_another_request() {
    let mut process = CustodianProcess::start();
    let mut stream = process.connect();
    write!(stream, "POST /v1/council HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/cbor\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n", MAX_BODY_BYTES * 2).unwrap();
    stream.write_all(&vec![0; MAX_BODY_BYTES + 1]).unwrap();
    // No remaining chunk bytes, CRLF or final chunk. The app must stop at its
    // decoded-body cap, then close the socket instead of waiting for the rest.
    assert_final_response_and_eof(&mut stream, 413);
    process.assert_healthy();

    let mut stream = process.connect();
    stream.write_all(b"POST /v1/council HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/cbor\r\nTransfer-Encoding: chunked\r\n\r\ninvalid\r\nPOST /v1/council HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/cbor\r\nContent-Length: 5\r\n\r\n\x64Ping").unwrap();
    // The malformed chunk's buffered remainder must not be treated as a second
    // request on a potentially pooled proxy connection.
    assert_final_response_and_eof(&mut stream, 413);
    process.assert_healthy();
}
