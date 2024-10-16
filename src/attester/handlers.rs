use hyper::{body::to_bytes, Body, Request, Response, StatusCode};
use serde_json::json;
use std::convert::Infallible;
use std::sync::Arc;
use once_cell::sync::Lazy;
use attestation_agent::{AttestationAPIs, AttestationAgent, InitdataResult};

use crate::attester::structs::*;

// Initialize an Arc-wrapped AttestationAgent lazily
// the attestation agent provides APIs to interact with the secure hardware features
static ATTESTATION_AGENT: Lazy<Arc<AttestationAgent>> = Lazy::new(|| {
    let config_path = None;
    Arc::new(AttestationAgent::new(config_path)
        .expect("Failed to create an AttestationAgent"))
});

/// Handles attestation evidence request.
/// 
/// Attestation evidence is: 
/// 1) The current state of the TEE, such as its RTMR measurements,
/// 2) The runtime data that is included in the request. 
///     This can be up to 64 bytes, usually acting as a nonce to prevent replay
///     or the hash of some other data
/// 3) A signature of 1) and 2) above, which needs to be checked against
///     a registry of enclave public keys. 
///     Intel maintains a pccs, and you can configure which service to use 
///     by modifying /etc/sgx_default_qcnl.conf
/// 
/// See https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_TDX_DCAP_Quoting_Library_API.pdf
/// Section 2.3.2 for more details
pub async fn attestation_evidence_handler(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    // parse the request body
    let body_bytes = match to_bytes(req.into_body()).await {
        Ok(bytes) => bytes,
        Err(_) => {
            let error_response = json!({ "error": "Invalid request body" }).to_string();
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from(error_response))
                .unwrap());
        }
    };

    // Deserialize the request body into the appropriate struct
    let evidence_request: AttestationEvidenceRequest = match serde_json::from_slice(&body_bytes) {
        Ok(request) => request,
        Err(_) => {
            let error_response = json!({ "error": "Invalid JSON in request body" }).to_string();
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from(error_response))
                .unwrap());
        }
    };

    // Get the evidence from the attestation agent
    let evidence = ATTESTATION_AGENT.get_evidence(evidence_request.runtime_data.as_slice())
        .await
        .map_err(|e| format!("Error while getting evidence: {:?}", e))
        .unwrap();

    // Return the evidence as a response
    let response_body = AttestationEvidenceResponse { evidence };
    let response_json = serde_json::to_string(&response_body).unwrap();
    Ok(Response::new(Body::from(response_json)))
}

/// Handles extend runtime measurement request.
pub async fn attestation_extend_runtime_measurement_handler(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    let body_bytes = match to_bytes(req.into_body()).await {
        Ok(bytes) => bytes,
        Err(_) => {
            let error_response = json!({ "error": "Invalid request body" }).to_string();
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from(error_response))
                .unwrap());
        }
    };

    let measurement_request: ExtendRuntimeMeasurementRequest = match serde_json::from_slice(&body_bytes) {
        Ok(request) => request,
        Err(_) => {
            let error_response = json!({ "error": "Invalid JSON in request body" }).to_string();
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from(error_response))
                .unwrap());
        }
    };

    ATTESTATION_AGENT.extend_runtime_measurement(
        &measurement_request.domain, 
        &measurement_request.operation, 
        &measurement_request.content, 
        measurement_request.register_index
    )
    .await
    .map_err(|e| format!("Error while extending runtime measurement: {:?}", e))
    .unwrap();

    Ok(Response::new(Body::empty()))
}

/// Handles check init data request.
/// 
/// For Intel TDX, the init_data are the 48 bytes in MRCONFIGID.
/// MRCONFIGID is a fingerprint of software that is setup by the host
/// (i.e. the person or platform providing the hardware), such as 
/// the OS that the guest application runs on.
/// 
/// The init_data feature is not supported for AzTdxVtpm because their secure boot
/// works differently than default TDX, 
/// But the route is available here in case Sesimic wants to use it in the future.
pub async fn attestation_check_init_data_handler(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    let body_bytes = match to_bytes(req.into_body()).await {
        Ok(bytes) => bytes,
        Err(_) => {
            let error_response = json!({ "error": "Invalid request body" }).to_string();
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from(error_response))
                .unwrap());
        }
    };

    let init_data_request: CheckInitDataRequest = match serde_json::from_slice(&body_bytes) {
        Ok(request) => request,
        Err(_) => {
            let error_response = json!({ "error": "Invalid JSON in request body" }).to_string();
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from(error_response))
                .unwrap());
        }
    };

    let init_data_result = ATTESTATION_AGENT.check_init_data(init_data_request.init_data.as_slice())
        .await
        .map_err(|e| format!("Error while checking init data: {:?}", e))
        .unwrap();

    let check_passed = match init_data_result {
        InitdataResult::Ok => true,
        InitdataResult::Unsupported => false,
    };
    
    let response_body = CheckInitDataResponse { check_passed };
    let response_json = serde_json::to_string(&response_body).unwrap();
    Ok(Response::new(Body::from(response_json)))
}

/// Handles TEE type request, which checks the type of enclave hardware being used
pub async fn attestation_tee_type_handler(_: Request<Body>) -> Result<Response<Body>, Infallible> {
    let tee_type = ATTESTATION_AGENT.get_tee_type();

    let response_body = TeeTypeResponse { tee_type };
    let response_json = serde_json::to_string(&response_body).unwrap();
    Ok(Response::new(Body::from(response_json)))
}