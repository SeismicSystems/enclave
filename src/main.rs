mod attester;
mod signing;
mod tx_io;
mod utils;

use anyhow::{Context, Result};
use attestation_agent::{AttestationAPIs, AttestationAgent};
use hyper::{Body, Request, Response, Server, StatusCode};
use log::debug;
use routerify::{prelude::*, Middleware, RequestInfo, Router, RouterService};
use std::convert::Infallible;
use std::net::SocketAddr;

use attester::handlers::*;
use signing::handlers::*;
use tx_io::handlers::*;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize the logger
    env_logger::init();

    // configure the attestation agent
    // Not currently used or configured, but it will be later on
    let aa = AttestationAgent::new(None).context("Failed to create an AttestationAgent")?;
    debug!("Detected TEE type: {:?}", aa.get_tee_type());

    // create the server
    let addr = SocketAddr::from(([127, 0, 0, 1], 7878));
    let router = Router::builder()
        .middleware(Middleware::pre(logger))
        .post("/attestation/attester/evidence", attestation_evidence_handler)
        .post("/attestation/attester/extend_runtime_measurement", attestation_extend_runtime_measurement_handler)
        .post("/attestation/attester/check_init_data", attestation_check_init_data_handler) 
        .post("/attestation/attester/tee_type", attestation_tee_type_handler)
        // .post("/attestation/get_token", attestation_get_token_handler) // gets evidence from the attester, submits it to another service like AS or KBS, returns the token
        .post("/signing/sign", secp256k1_sign_handler)
        .post("/siging/verify", secp256k1_verify_handler)
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
