use attestation_agent::AttestationAPIs;
use hyper::{body::to_bytes, Body, Request, Response};
use std::convert::Infallible;

use super::structs::*;
use crate::utils::respone_utils::{invalid_json_body_resp, invalid_req_body_resp};
use crate::ATTESTATION_AGENT;

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
pub async fn attestation_get_evidence_handler(
    req: Request<Body>,
) -> Result<Response<Body>, Infallible> {
    // parse the request body
    let body_bytes = match to_bytes(req.into_body()).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return Ok(invalid_req_body_resp());
        }
    };

    // Deserialize the request body into the appropriate struct
    let evidence_request: AttestationGetEvidenceRequest = match serde_json::from_slice(&body_bytes)
    {
        Ok(request) => request,
        Err(_) => {
            return Ok(invalid_json_body_resp());
        }
    };

    // Get the evidence from the attestation agent
    let coco_aa = ATTESTATION_AGENT.get().unwrap();
    let evidence = coco_aa
        .get_evidence(evidence_request.runtime_data.as_slice())
        .await
        .map_err(|e| format!("Error while getting evidence: {:?}", e))
        .unwrap();

    // Return the evidence as a response
    let response_body = AttestationGetEvidenceResponse { evidence };
    let response_json = serde_json::to_string(&response_body).unwrap();
    Ok(Response::new(Body::from(response_json)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::init_coco_aa;
    use hyper::{Body, Request, Response, StatusCode};
    use serde_json::Value;

    #[tokio::test]
    async fn test_attestation_evidence_handler_valid_request() {
        // NOTE: This test will run with the Sample TEE Type
        // because it doesn't run with sudo privileges

        init_coco_aa().expect("Failed to initialize AttestationAgent");
        
        // Mock a valid AttestationGetEvidenceRequest
        let runtime_data = "nonce".as_bytes(); // Example runtime data
        let evidence_request = AttestationGetEvidenceRequest {
            runtime_data: runtime_data.to_vec(),
        };

        // Serialize the request to JSON
        let payload_json = serde_json::to_string(&evidence_request).unwrap();

        // Create a request
        let req = Request::builder()
            .method("POST")
            .uri("/attestation/attester/evidence")
            .header("Content-Type", "application/json")
            .body(Body::from(payload_json))
            .unwrap();

        // Call the handler
        let res: Response<Body> = attestation_get_evidence_handler(req).await.unwrap();

        // Check that the response status is 200 OK
        assert_eq!(res.status(), StatusCode::OK);

        // Parse and check the response body
        let body = hyper::body::to_bytes(res.into_body()).await.unwrap();
        let get_evidence_resp: AttestationGetEvidenceResponse =
            serde_json::from_slice(&body).unwrap();

        // Ensure the response is not empty
        assert!(!get_evidence_resp.evidence.is_empty());
    }

    #[tokio::test]
    async fn test_attestation_evidence_handler_invalid_json() {
        // Create a request with invalid JSON body
        let req = Request::builder()
            .method("POST")
            .uri("/attestation/attester/evidence")
            .header("Content-Type", "application/json")
            .body(Body::from("Invalid JSON"))
            .unwrap();

        // Call the handler
        let res: Response<Body> = attestation_get_evidence_handler(req).await.unwrap();

        // Check that the response status is 400 Bad Request
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        // Parse and check the response body
        let body_bytes = hyper::body::to_bytes(res.into_body()).await.unwrap();
        let response_json: Value = serde_json::from_slice(&body_bytes).unwrap();

        assert_eq!(response_json["error"], "Invalid JSON in request body");
    }
}
