use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use tiny_http::{Response, Server};

fn connect(server: &Server) -> TcpStream {
    let stream = TcpStream::connect(server.server_addr().to_ip().unwrap()).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
}

#[test]
fn unsupported_versions_reject_without_waiting_for_headers_or_body() {
    let server = Server::http("127.0.0.1:0").unwrap();
    for version in ["2.0", "3.0"] {
        for suffix in ["", "Host: localhost\r\nContent-Length: 5\r\n\r\n"] {
            let mut stream = connect(&server);
            stream
                .write_all(format!("POST / HTTP/{version}\r\n{suffix}").as_bytes())
                .unwrap();
            // Do not close the client's write side or fulfill the body: the
            // parser itself must emit 505 and close without constructing a Request.
            let mut response = String::new();
            stream.read_to_string(&mut response).unwrap();
            assert!(response.starts_with("HTTP/1.1 505 "), "{}", response);
            assert!(response
                .to_ascii_lowercase()
                .contains("\r\nconnection: close\r\n"));
            assert!(server.try_recv().unwrap().is_none());
        }
    }
}

#[test]
fn version_rejection_preserves_prior_pipelined_response_order() {
    let server = Server::http("127.0.0.1:0").unwrap();
    let mut stream = connect(&server);
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\nPOST / HTTP/2.0\r\n")
        .unwrap();
    let request = server
        .recv_timeout(Duration::from_secs(3))
        .unwrap()
        .unwrap();
    request.respond(Response::from_string("ok")).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200 "), "{}", response);
    assert!(response.contains("\r\n\r\nokHTTP/1.1 505 "), "{}", response);
    assert_eq!(response.matches("HTTP/1.1 ").count(), 2);
    assert!(server.try_recv().unwrap().is_none());
}
