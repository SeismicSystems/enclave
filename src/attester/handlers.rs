use hyper::{body::to_bytes, Body, Request, Response, StatusCode};
use serde_json::json;
use std::convert::Infallible;
use std::sync::Arc;
use once_cell::sync::Lazy;
use attestation_agent::{AttestationAPIs, AttestationAgent};

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