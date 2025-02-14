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
    server::conn::{http1, http2},
    service::service_fn,
    Method, Request, Response, StatusCode,
};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use tokio::net::TcpListener;

// #[derive(Clone)]
// // An Executor that uses the tokio runtime.
// pub struct TokioExecutor;

// // Implement the `hyper::rt::Executor` trait for `TokioExecutor` so that it can be used to spawn
// // tasks in the hyper runtime.
// // An Executor allows us to manage execution of tasks which can help us improve the efficiency and
// // scalability of the server.
// impl<F> hyper::rt::Executor<F> for TokioExecutor
// where
//     F: std::future::Future + Send + 'static,
//     F::Output: Send + 'static,
// {
//     fn execute(&self, fut: F) {
//         tokio::task::spawn(fut);
//     }
// }

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
    match (req.method(), req.uri().path()) {
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
