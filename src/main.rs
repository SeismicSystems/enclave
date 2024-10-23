mod coco_aa;
mod coco_as;
mod genesis;
mod signing;
mod tx_io;
mod utils;

use anyhow::Result;
use hyper::{Body, Request, Response, Server, StatusCode};
use once_cell::sync::OnceCell;
use routerify::{prelude::*, Middleware, RequestInfo, Router, RouterService};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use coco_aa::handlers::*;
use coco_as::handlers::*;
use genesis::handlers::*;
use signing::handlers::*;
use tx_io::handlers::*;

use attestation_agent::AttestationAgent;
#[cfg(feature = "verifier")]
use attestation_service::{config::Config, AttestationService};

#[cfg(feature = "verifier")]
static ATTESTATION_SERVICE: OnceCell<Arc<AttestationService>> = OnceCell::new();
static ATTESTATION_AGENT: OnceCell<Arc<AttestationAgent>> = OnceCell::new();

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize the logger
    env_logger::init();

    // Initialize the Attestation Agent and Attestation Service
    init_coco_aa()?;
    #[cfg(feature = "verifier")]
    init_coco_as().await?;

    // create the server
    let addr = SocketAddr::from(([0, 0, 0, 0], 7878));
    let builder = Router::builder()
        .middleware(Middleware::pre(logger))
        .get("/genesis/data", genesis_get_data_handler)
        .post(
            "/attestation/aa/get_evidence",
            attestation_get_evidence_handler,
        )
        .post("/signing/sign", secp256k1_sign_handler)
        .post("/signing/verify", secp256k1_verify_handler)
        .post("/tx_io/encrypt", tx_io_encrypt_handler)
        .post("/tx_io/decrypt", tx_io_decrypt_handler)
        .err_handler_with_info(error_handler);

    #[cfg(feature = "verifier")]
    let builder = builder.post(
        "/attestation/as/eval_evidence",
        attestation_eval_evidence_handler,
    );
    
    let router = builder.build().unwrap();
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

fn init_coco_aa() -> Result<()> {
    // Check if the service is already initialized
    // This helps with multithreaded testing
    if ATTESTATION_AGENT.get().is_some() {
        // AttestationAgent is already initialized, so we skip re-initialization.
        return Ok(());
    }

    let config_path = None;
    let coco_aa = AttestationAgent::new(config_path).expect("Failed to create an AttestationAgent");
    ATTESTATION_AGENT
        .set(Arc::new(coco_aa))
        .map_err(|_| anyhow::anyhow!("Failed to set AttestationAgent"))?;

    Ok(())
}

#[cfg(feature = "verifier")]
async fn init_coco_as() -> Result<()> {
    // Check if the service is already initialized
    // This helps with multithreaded testing
    if ATTESTATION_SERVICE.get().is_some() {
        // AttestationService is already initialized, so we skip re-initialization.
        return Ok(());
    }

    // TODO: load a real config with a policy once we have one
    // let config_path_str = "path/to/config.json";
    // let config_path = std::path::Path::new(config_path_str);
    // let config = Config::try_from(config_path).expect("Failed to load AttestationService config");

    // Initialize the AttestationService
    let config = Config::default();
    let coco_as = AttestationService::new(config)
        .await
        .expect("Failed to create an AttestationService");
    ATTESTATION_SERVICE
        .set(Arc::new(coco_as))
        .map_err(|_| anyhow::anyhow!("Failed to set AttestationService"))?;

    Ok(())
}
