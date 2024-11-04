use anyhow::Result;
use hyper::{Body, Request, Response, Server, StatusCode};
use routerify::{prelude::*, Middleware, RequestInfo, Router, RouterService};
use std::convert::Infallible;
use std::net::SocketAddr;

use tee_service::{
    coco_aa::handlers::*, 
    coco_as::handlers::*, 
    genesis::handlers::*, 
    signing::handlers::*,
    tx_io::handlers::*,
};

/// Initializes a server with the given address and handlers
#[tokio::main]
async fn main() -> Result<()> {
    // Initialize the logger
    env_logger::init();

    // Initialize the Attestation Agent and Attestation Service
    tee_service::init_coco_aa()?;
    tee_service::init_coco_as(None).await?;

    // create the server
    let addr = SocketAddr::from(([127, 0, 0, 1], 7878));
    let router = Router::builder()
        .middleware(Middleware::pre(logger))
        .get("/genesis/data", genesis_get_data_handler)
        .post(
            "/attestation/aa/get_evidence",
            attestation_get_evidence_handler,
        )
        .post(
            "/attestation/as/eval_evidence",
            attestation_eval_evidence_handler,
        )
        .post("/signing/sign", secp256k1_sign_handler)
        .post("/signing/verify", secp256k1_verify_handler)
        .post("/tx_io/encrypt", tx_io_encrypt_handler)
        .post("/tx_io/decrypt", tx_io_decrypt_handler)
        .err_handler_with_info(error_handler)
        .build()
        .unwrap();
    let service = RouterService::new(router).unwrap();
    let server = Server::bind(&addr).serve(service);

    println!("Listening on http://{}\n", addr);

    if let Err(e) = server.await {
        eprintln!("Server error: {}", e);
    }

    Ok(())
}

// A middleware which logs an http request.
async fn logger(req: Request<Body>) -> Result<Request<Body>, Infallible> {
    println!(
        "{} {} {}",
        req.remote_addr(),
        req.method(),
        req.uri().path()
    );
    Ok(req)
}

// Define an error handler function which will accept the `routerify::Error`
// and the request information and generates an appropriate response.
async fn error_handler(err: routerify::RouteError, _: RequestInfo) -> Response<Body> {
    println!("\n\nError: {:?}\n\n", err);
    eprintln!("{}", err);
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(Body::from(format!("Something went wrong: {}", err)))
        .unwrap()
}
