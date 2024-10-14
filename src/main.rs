mod tx_io;

use anyhow::{Context, Result};
use log::debug;
use attestation_agent::AttestationAgent;
use attestation_agent::AttestationAPIs;

use std::convert::Infallible;
use hyper::{Body, Request, Response, Server, StatusCode};
use std::net::SocketAddr;
use routerify::prelude::*;
use routerify::{Middleware, Router, RouterService, RequestInfo};

use tx_io::handlers::*;


#[tokio::main]
async fn main() -> Result<()> {
    // Initialize the logger
    env_logger::init();

    // Proper error handling
    let aa = AttestationAgent::new(None)
        .context("Failed to create an AttestationAgent")?;
    debug!("Detected TEE type: {:?}", aa.get_tee_type());

    let addr = SocketAddr::from(([127, 0, 0, 1], 7878));

    let router =  Router::builder()
    // Specify the state data which will be available to every route handlers,
    // error handler and middlewares.
    .middleware(Middleware::pre(logger))
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
    println!("{} {} {}", req.remote_addr(), req.method(), req.uri().path());
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

