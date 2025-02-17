use http_body_util::Full;
use hyper::{
    body::{Body, Bytes},
    Request, Response,
};
use jsonrpsee::core::RpcResult;

use super::att_genesis_data;
use seismic_enclave::{request_types::genesis::*, rpc_bad_argument_error};

/// Handles request to get genesis data.
///
/// At genesis the network generates network wide constants, such as the transaction encryption keypair
/// This function returns the genesis data to the client
/// Along with an attestation of such data that can be verified with the attestation/as/eval_evidence endpoint
///
/// Currently uses hardcoded values for testing purposes, which will be updated later
pub async fn genesis_get_data_handler(
    _: Request<impl Body>,
) -> Result<Response<Full<Bytes>>, anyhow::Error> {
    let (genesis_data, evidence) = att_genesis_data().await.unwrap();

    // Return the evidence as a response
    let response_body = GenesisDataResponse {
        data: genesis_data,
        evidence,
    };
    let response_json = serde_json::to_string(&response_body).unwrap();
    Ok(Response::new(Full::new(Bytes::from(response_json))))
}

pub async fn rpc_genesis_get_data_handler() -> RpcResult<GenesisDataResponse> {
    let (genesis_data, evidence) = att_genesis_data()
        .await
        .map_err(|e| rpc_bad_argument_error(e))?;

    // Return the evidence as a response
    Ok(GenesisDataResponse {
        data: genesis_data,
        evidence,
    })
}

#[allow(unused_imports)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        coco_as::handlers::attestation_eval_evidence_handler, coco_as::into_original::*,
        init_as_policies, init_coco_aa, init_coco_as, utils::test_utils::is_sudo,
    };
    use http_body_util::BodyExt;
    use hyper::StatusCode;
    use kbs_types::Tee;
    use seismic_enclave::request_types::coco_as::*;
    use serde_json::Value;
    use serial_test::serial;
    use sha2::{Digest, Sha256};

    use attestation_service::Data as OriginalData;
    use attestation_service::HashAlgorithm as OriginalHashAlgorithm;
    use seismic_enclave::request_types::coco_as::Data as ApiData;
    use seismic_enclave::request_types::coco_as::HashAlgorithm as ApiHashAlgorithm;

    #[tokio::test]
    #[serial(attestation_agent)]
    async fn test_genesis_get_data_handler_success_basic() {
        // Initialize ATTESTATION_AGENT
        init_coco_aa().expect("Failed to initialize AttestationAgent");

        // Create a request
        let req: Request<Full<Bytes>> = Request::builder()
            .method("GET")
            .uri("/genesis/data")
            .body(Full::default())
            .unwrap();

        // Call the handler
        let res: Response<Full<Bytes>> = genesis_get_data_handler(req).await.unwrap();

        // Check that the response status is 200 OK
        assert_eq!(res.status(), StatusCode::OK, "{res:?}");

        // Parse and check the response body
        let body: Bytes = res.into_body().collect().await.unwrap().to_bytes();
        let response: GenesisDataResponse = serde_json::from_slice(&body).unwrap();

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

        // Initialize ATTESTATION_AGENT and ATTESTATION_SERVICE
        init_coco_aa().expect("Failed to initialize AttestationAgent");
        init_coco_as(None)
            .await
            .expect("Failed to initialize AttestationService");
        init_as_policies()
            .await
            .expect("Failed to initialize AS policies");

        // Make a genesis data request
        let req: Request<Full<Bytes>> = Request::builder()
            .method("GET")
            .uri("/genesis/data")
            .body(Full::default())
            .unwrap();
        let res: Response<Full<Bytes>> = genesis_get_data_handler(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK, "{res:?}");
        let body: Bytes = res.into_body().collect().await.unwrap().to_bytes();
        let genesis_data_response: GenesisDataResponse = serde_json::from_slice(&body).unwrap();

        // Submit the genesis data to the attestation service
        let bytes = genesis_data_response.data.to_bytes().unwrap();
        let genesis_data_hash: [u8; 32] = Sha256::digest(bytes).into();

        let tdx_eval_request = AttestationEvalEvidenceRequest {
            evidence: genesis_data_response.evidence,
            tee: Tee::AzTdxVtpm,
            runtime_data: Some(ApiData::Raw(genesis_data_hash.to_vec())), // Check that the genesis data hash matches the evidence report_data
            runtime_data_hash_algorithm: None,
            policy_ids: vec!["allow".to_string()],
        };
        let payload_json = serde_json::to_string(&tdx_eval_request).unwrap();
        let req: Request<Full<Bytes>> = Request::builder()
            .method("POST")
            .uri("/attestation/as/eval_evidence")
            .header("Content-Type", "application/json")
            .body(Full::from(Bytes::from(payload_json)))
            .unwrap();
        let res: Response<Full<Bytes>> = attestation_eval_evidence_handler(req).await.unwrap();

        // Check that the eval evidence response
        assert_eq!(res.status(), StatusCode::OK, "{res:?}");
        // Parse and check the response body
        let body: Bytes = res.into_body().collect().await.unwrap().to_bytes();
        let eval_evidence_response: AttestationEvalEvidenceResponse =
            serde_json::from_slice(&body).unwrap();

        assert!(eval_evidence_response.eval);
    }
}
