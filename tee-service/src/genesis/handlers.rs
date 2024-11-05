use hyper::{Body, Request, Response};
use std::convert::Infallible;

use super::att_genesis_data;
use tee_service_api::request_types::genesis::*;

/// Handles request to get genesis data.
///
/// At genesis the network generates network wide constants, such as the transaction encryption keypair
/// This function returns the genesis data to the client
/// Along with an attestation of such data that can be verified with the attestation/as/eval_evidence endpoint
///
/// Currently uses hardcoded values for testing purposes, which will be updated later
pub async fn genesis_get_data_handler(_: Request<Body>) -> Result<Response<Body>, Infallible> {
    let (genesis_data, evidence) = att_genesis_data().await.unwrap();

    // Return the evidence as a response
    let response_body = GenesisDataResponse {
        data: genesis_data,
        evidence,
    };
    let response_json = serde_json::to_string(&response_body).unwrap();
    Ok(Response::new(Body::from(response_json)))
}

#[allow(unused_imports)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        coco_as::handlers::attestation_eval_evidence_handler, coco_as::into_original::*,
        init_as_policies, init_coco_aa, init_coco_as, utils::test_utils::is_sudo,
    };
    use hyper::{Body, Request, Response, StatusCode};
    use kbs_types::Tee;
    use serde_json::Value;
    use serial_test::serial;
    use sha2::{Digest, Sha256};
    use tee_service_api::request_types::coco_as::*;

    use attestation_service::Data as OriginalData;
    use attestation_service::HashAlgorithm as OriginalHashAlgorithm;
    use tee_service_api::request_types::coco_as::Data as ApiData;
    use tee_service_api::request_types::coco_as::HashAlgorithm as ApiHashAlgorithm;

    #[tokio::test]
    #[serial(attestation_agent)]
    async fn test_genesis_get_data_handler_success_basic() {
        // Initialize ATTESTATION_AGENT
        init_coco_aa().expect("Failed to initialize AttestationAgent");

        // Create a request
        let req = Request::builder()
            .method("GET")
            .uri("/genesis/data")
            .body(Body::empty())
            .unwrap();

        // Call the handler
        let res: Response<Body> = genesis_get_data_handler(req).await.unwrap();

        // Check that the response status is 200 OK
        assert_eq!(res.status(), StatusCode::OK);

        // Parse and check the response body
        let body_bytes = hyper::body::to_bytes(res.into_body()).await.unwrap();
        let response: GenesisDataResponse = serde_json::from_slice(&body_bytes).unwrap();

        // assert that the attestation is not empty
        assert!(!response.evidence.is_empty());
    }

    #[tokio::test]
    #[serial(attestation_agent, attestation_service)]
    async fn test_genesis_get_data_handler_evidence_verifies() {
        // handle set up permissions
        if !is_sudo() {
            eprintln!("test_eval_evidence_az_tdx: skipped (requires sudo privileges)");
            return;
        }

        // Initialize ATTESTATION_AGENT
        init_coco_aa().expect("Failed to initialize AttestationAgent");

        // Make a genesis data request
        let req = Request::builder()
            .method("GET")
            .uri("/genesis/data")
            .body(Body::empty())
            .unwrap();
        let res: Response<Body> = genesis_get_data_handler(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body_bytes = hyper::body::to_bytes(res.into_body()).await.unwrap();
        let genesis_data_response: GenesisDataResponse =
            serde_json::from_slice(&body_bytes).unwrap();

        // Submit the genesis data to the attestation service
        init_coco_as(None)
            .await
            .expect("Failed to initialize AttestationService");
        init_as_policies()
            .await
            .expect("Failed to initialize AS policies");

        let genesis_data_hash: [u8; 32] =
            Sha256::digest(genesis_data_response.data.to_bytes()).into();

        let tdx_eval_request = AttestationEvalEvidenceRequest {
            evidence: genesis_data_response.evidence,
            tee: Tee::AzTdxVtpm,
            runtime_data: Some(ApiData::Raw(genesis_data_hash.to_vec())), // Check that the genesis data hash matches the evidence report_data
            runtime_data_hash_algorithm: None,
            policy_ids: vec!["allow".to_string()],
        };
        let payload_json = serde_json::to_string(&tdx_eval_request).unwrap();
        let req = Request::builder()
            .method("POST")
            .uri("/attestation/as/eval_evidence")
            .header("Content-Type", "application/json")
            .body(Body::from(payload_json))
            .unwrap();
        let res: Response<Body> = attestation_eval_evidence_handler(req).await.unwrap();

        // Check that the eval evidence response
        assert_eq!(res.status(), StatusCode::OK);
        // Parse and check the response body
        let body = hyper::body::to_bytes(res.into_body()).await.unwrap();
        let eval_evidence_response: AttestationEvalEvidenceResponse =
            serde_json::from_slice(&body).unwrap();

        assert!(eval_evidence_response.eval);
    }
}
