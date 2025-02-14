use crate::coco_aa::handlers::*;
use crate::coco_as::handlers::*;
use crate::genesis::handlers::*;
use crate::signing::handlers::*;
use crate::snapsync::handlers::*;
use crate::tx_io::handlers::*;

use anyhow::Result;
use http_body_util::Full;
use hyper::{
    body::{Body, Bytes},
    server::conn::http1,
    service::service_fn,
    Method, Request, Response, StatusCode,
};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use tokio::net::TcpListener;

pub async fn start_server(addr: SocketAddr) -> Result<()> {
    // Initialize services
    crate::init_coco_aa()?;
    crate::init_coco_as(None).await?;

    let listener = TcpListener::bind(&addr).await?;
    println!("Listening on http://{}", addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);

        tokio::task::spawn(async move {
            let service = service_fn(route_req);

            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                println!("Failed to serve connection: {:?}", err);
            }
        });
    }
}

pub async fn route_req(req: Request<impl Body>) -> Result<Response<Full<Bytes>>> {
    log_request(&req);
    match (req.method(), req.uri().path()) {
        // Health check
        (&Method::GET, "/health") => health_check(req).await,

        // Genesis
        (&Method::GET, "/genesis/data") => genesis_get_data_handler(req).await,

        // Attestation
        (&Method::POST, "/attestation/aa/get_evidence") => {
            attestation_get_evidence_handler(req).await
        }
        (&Method::POST, "/attestation/as/eval_evidence") => {
            attestation_eval_evidence_handler(req).await
        }

        // Signing
        (&Method::POST, "/signing/sign") => secp256k1_sign_handler(req).await,
        (&Method::POST, "/signing/verify") => secp256k1_verify_handler(req).await,

        // SnapSync
        (&Method::POST, "/snapsync/provide_backup") => provide_snapsync_handler(req).await,

        // Transaction I/O
        (&Method::POST, "/tx_io/encrypt") => tx_io_encrypt_handler(req).await,
        (&Method::POST, "/tx_io/decrypt") => tx_io_decrypt_handler(req).await,

        // Default: 404 Not Found
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::from(Bytes::from("route not found")))
            .unwrap()),
    }
}

async fn health_check(_: Request<impl Body>) -> Result<Response<Full<Bytes>>, anyhow::Error> {
    Ok(Response::new(Full::new(Bytes::from("OK"))))
}

fn log_request(req: &Request<impl Body>) {
    let method = req.method().to_string();
    let uri = req.uri().to_string();
    let log = format!("{} {}", method, uri);
    println!("{log}");
}

#[cfg(test)]
mod test {
    use super::start_server;
    use crate::utils::test_utils::is_sudo;
    use seismic_enclave::client::http_client::TeeHttpClient;
    use seismic_enclave::client::http_client::{
        TEE_DEFAULT_ENDPOINT_ADDR, TEE_DEFAULT_ENDPOINT_PORT,
    };
    use seismic_enclave::request_types::tx_io::*;
    use seismic_enclave::TeeAPI;

    use secp256k1::PublicKey;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use tokio::time::Duration;
    use tokio::time::Instant;

    #[ignore]
    #[tokio::test]
    async fn test_server_tx_io_req() {
        // handle set up permissions
        if !is_sudo() {
            eprintln!("test_server_tx_io_req: skipped (requires sudo privileges)");
            return;
        }

        // spawn a seperate thread for the server, otherwise the test will hang
        let addr = SocketAddr::from((TEE_DEFAULT_ENDPOINT_ADDR, TEE_DEFAULT_ENDPOINT_PORT));
        let _server_handle = tokio::spawn(start_server(addr));
        let wait_duration = Duration::from_secs(2);
        wait_for_server(&format!("{}/health", addr), wait_duration)
            .await
            .unwrap();

        // make the request struct
        let data_to_encrypt = vec![72, 101, 108, 108, 111];
        let mut nonce = vec![0u8; 4]; // 4 leading zeros
        nonce.extend_from_slice(&(12345678u64).to_be_bytes()); // Append the 8-byte u64
        let encryption_request = IoEncryptionRequest {
            key: PublicKey::from_str(
                "03e31e68908a6404a128904579c677534d19d0e5db80c7d9cf4de6b4b7fe0518bd",
            )
            .unwrap(),
            data: data_to_encrypt.clone(),
            nonce: nonce.clone().into(),
        };

        // make the http request
        let http_cleint = TeeHttpClient::default();
        let encryption_response = http_cleint.tx_io_encrypt(encryption_request).await.unwrap();

        // check the response
        assert!(!encryption_response.encrypted_data.is_empty());

        let decryption_request = IoDecryptionRequest {
            key: PublicKey::from_str(
                "03e31e68908a6404a128904579c677534d19d0e5db80c7d9cf4de6b4b7fe0518bd",
            )
            .unwrap(),
            data: encryption_response.encrypted_data,
            nonce: nonce.into(),
        };
        let decryption_response = http_cleint.tx_io_decrypt(decryption_request).await.unwrap();
        assert_eq!(decryption_response.decrypted_data, data_to_encrypt);
    }

    async fn wait_for_server(
        addr: &str,
        timeout: Duration,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let start = Instant::now();
        while start.elapsed() < timeout {
            if reqwest::get(addr).await.is_ok() {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Err("Server did not start in time".into())
    }
}
