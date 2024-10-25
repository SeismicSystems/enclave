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
use std::fs;
use tokio::sync::RwLock;

use coco_aa::handlers::*;
use coco_as::handlers::*;
use genesis::handlers::*;
use signing::handlers::*;
use tx_io::handlers::*;

use attestation_agent::AttestationAgent;
use attestation_service::{config::Config, AttestationService};
use base64::Engine;

static ATTESTATION_SERVICE: OnceCell<Arc<RwLock<AttestationService>>> = OnceCell::new();
static ATTESTATION_AGENT: OnceCell<Arc<AttestationAgent>> = OnceCell::new();

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize the logger
    env_logger::init();

    // Initialize the Attestation Agent and Attestation Service
    init_coco_aa()?;
    init_coco_as(None).await?;
    // init_as_policies().await?;

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

async fn init_coco_as(config: Option<Config>) -> Result<()> {
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

    let config = match config {
        Some(config) => config,
        None => Config::default(),
    };

    // Initialize the AttestationService
    let coco_as = AttestationService::new(config)
        .await
        .expect("Failed to create an AttestationService");
    let lock = tokio::sync::RwLock::new(coco_as);
    ATTESTATION_SERVICE
        .set(Arc::new(lock))
        .map_err(|_| anyhow::anyhow!("Failed to set AttestationService"))?;

    // initialize the policies
    init_as_policies().await?;
    Ok(())
}

/// Initializes the AS policies from the policies directory
/// While every AS eval request checks that the evidence was created by a real enclave
/// A policy defines the expected values of that enclave. 
/// 
/// For example, the important values for AxTdxVtpm are the MRSEAM and MRTD values,
/// which respectively fingerprint the TDX module and the guest firmware that are running
pub async fn init_as_policies() -> Result<()> {
    let coco_as = ATTESTATION_SERVICE.get().unwrap();
    let mut writeable_as = coco_as.write().await; 
    
    let policy_dir = std::path::Path::new("./src/coco_as/examples/policies");
    for entry in fs::read_dir(policy_dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() {
            let policy_name = path.file_stem().unwrap().to_str().unwrap();
            let policy = fs::read_to_string(&path)?;
            let policy_encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(policy);
            writeable_as.set_policy(policy_name.to_string(), policy_encoded).await?;
        }
    }
    
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use anyhow::Ok;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    #[tokio::test]
    async fn test() {
        let config = Config::default();
        println!("{:?}", config);
    }

    #[test]
    fn see_as_token() -> Result<()> {
        let as_token = std::fs::read_to_string("./src/coco_as/examples/as_token.txt").unwrap();
        let parts: Vec<&str> = as_token.splitn(3, '.').collect();
        let claims_b64 = parts[1];
        let claims_decoded_bytes = URL_SAFE_NO_PAD.decode(claims_b64)?;
        let claims_decoded_string = String::from_utf8(claims_decoded_bytes)?;
        let claims_pretty_str = serde_json::to_string_pretty(&claims_decoded_string)?;
        println!("{claims_pretty_str}");
        Ok(())
    }
}