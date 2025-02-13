use http_body_util::{BodyExt, Full};
use hyper::{
    body::{Body, Bytes},
    Request, Response,
};
use std::convert::Infallible;

use super::attest;
use seismic_enclave::errors::{invalid_json_body_resp, invalid_req_body_resp};
use seismic_enclave::request_types::coco_aa::*;

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
    req: Request<impl Body>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    // parse the request body
    let body_bytes: Bytes = match req.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return Ok(invalid_req_body_resp()),
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
    let evidence = attest(evidence_request.runtime_data.as_slice())
        .await
        .unwrap();

    // Return the evidence as a response
    let response_body = AttestationGetEvidenceResponse { evidence };
    let response_json = serde_json::to_string(&response_body).unwrap();
    Ok(Response::new(Full::new(Bytes::from(response_json))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::init_coco_aa;
    use crate::utils::test_utils::is_sudo;

    use hyper::StatusCode;
    use serde_json::Value;
    use serial_test::serial;

    #[tokio::test]
    #[serial(attestation_agent)]
    async fn test_attestation_evidence_handler_valid_request_sample() {
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
        let req: Request<Full<Bytes>> = Request::builder()
            .method("POST")
            .uri("/attestation/aa/get_evidence")
            .header("Content-Type", "application/json")
            .body(Full::from(Bytes::from(payload_json)))
            .unwrap();

        // Call the handler
        let res: Response<Full<Bytes>> = attestation_get_evidence_handler(req).await.unwrap();

        // Check that the response status is 200 OK
        assert_eq!(res.status(), StatusCode::OK, "{res:?}");

        // Parse and check the response body
        let body: Bytes = res.into_body().collect().await.unwrap().to_bytes();
        let get_evidence_resp: AttestationGetEvidenceResponse =
            serde_json::from_slice(&body).unwrap();

        // Ensure the response is not empty
        assert!(!get_evidence_resp.evidence.is_empty());
    }

    #[tokio::test]
    #[serial(attestation_agent)]
    async fn test_attestation_evidence_handler_aztdxvtpm_runtime_data() {
        // handle set up permissions
        if !is_sudo() {
            eprintln!("test_eval_evidence_az_tdx: skipped (requires sudo privileges)");
            return;
        }

        init_coco_aa().expect("Failed to initialize AttestationAgent");

        // Make requests with different runtime data and see they are different
        let runtime_data_1 = "nonce1".as_bytes();
        let evidence_request_1 = AttestationGetEvidenceRequest {
            runtime_data: runtime_data_1.to_vec(),
        };

        let runtime_data_2 = "nonce2".as_bytes();
        let evidence_request_2 = AttestationGetEvidenceRequest {
            runtime_data: runtime_data_2.to_vec(),
        };

        // Serialize the request to JSON
        let payload_json_1 = serde_json::to_string(&evidence_request_1).unwrap();
        let payload_json_2 = serde_json::to_string(&evidence_request_2).unwrap();

        // Create a request
        let req_1: Request<Full<Bytes>> = Request::builder()
            .method("POST")
            .uri("/attestation/aa/get_evidence")
            .header("Content-Type", "application/json")
            .body(Full::from(Bytes::from(payload_json_1)))
            .unwrap();
        let res_1: Response<Full<Bytes>> = attestation_get_evidence_handler(req_1).await.unwrap();

        let req_2: Request<Full<Bytes>> = Request::builder()
            .method("POST")
            .uri("/attestation/aa/get_evidence")
            .header("Content-Type", "application/json")
            .body(Full::from(Bytes::from(payload_json_2)))
            .unwrap();
        let res_2: Response<Full<Bytes>> = attestation_get_evidence_handler(req_2).await.unwrap();

        assert_eq!(res_1.status(), StatusCode::OK);
        assert_eq!(res_2.status(), StatusCode::OK);

        // Parse and check the response body
        let body_1: Bytes = res_1.into_body().collect().await.unwrap().to_bytes();
        let body_2: Bytes = res_2.into_body().collect().await.unwrap().to_bytes();
        let get_evidence_resp_1: AttestationGetEvidenceResponse =
            serde_json::from_slice(&body_1).unwrap();
        let get_evidence_resp_2: AttestationGetEvidenceResponse =
            serde_json::from_slice(&body_2).unwrap();

        assert_ne!(get_evidence_resp_1.evidence, get_evidence_resp_2.evidence);
    }

    #[tokio::test]
    async fn test_attestation_evidence_handler_invalid_json() {
        // Create a request with invalid JSON body
        let req: Request<Full<Bytes>> = Request::builder()
            .method("POST")
            .uri("/attestation/aa/get_evidence")
            .header("Content-Type", "application/json")
            .body(Full::from(Bytes::from("Invalid JSON")))
            .unwrap();

        // Call the handler
        let res: Response<Full<Bytes>> = attestation_get_evidence_handler(req).await.unwrap();

        // Check that the response status is 400 Bad Request
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        // Parse and check the response body
        let body: Bytes = res.into_body().collect().await.unwrap().to_bytes();
        let response_json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(response_json["error"], "Invalid JSON in request body");
    }
}
