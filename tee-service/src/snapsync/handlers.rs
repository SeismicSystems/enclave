use attestation_service::HashAlgorithm;
use hyper::{body::to_bytes, Body, Request, Response};
use sha2::{Digest, Sha256};
use std::convert::Infallible;

use crate::coco_as::{eval_att_evidence, parse_as_token_claims};
use tee_service_api::coco_as::ASCoreTokenClaims;
use tee_service_api::errors::{
    bad_evidence_response, invalid_json_body_resp, invalid_req_body_resp,
};
use tee_service_api::request_types::snapsync::*;

pub async fn provide_snapsync_handler(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    // parse the request body
    let body_bytes = match to_bytes(req.into_body()).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return Ok(invalid_req_body_resp());
        }
    };

    // Deserialize the request body into the appropriate struct
    let snapsync_request: SnapSyncRequest = match serde_json::from_slice(&body_bytes) {
        Ok(request) => request,
        Err(_) => {
            return Ok(invalid_json_body_resp());
        }
    };

    // verify the request attestation
    let pk_hash: [u8; 32] = Sha256::digest(snapsync_request.rsa_pk_pem.as_slice()).into();
    let eval_result = eval_att_evidence(
        snapsync_request.client_attestation,
        snapsync_request.tee,
        Some(attestation_service::Data::Raw(pk_hash.to_vec())),
        HashAlgorithm::Sha256,
        None,
        HashAlgorithm::Sha256,
        snapsync_request.policy_ids,
    )
    .await;

    let as_token: String = match eval_result {
        Ok(as_token) => as_token,
        Err(e) => {
            return Ok(bad_evidence_response(e));
        }
    };

    let claims: ASCoreTokenClaims = parse_as_token_claims(&as_token)
        .map_err(|e| format!("Error while parsing AS token: {:?}", e))
        .unwrap();

    println!("claims: {:?}", claims);
    // extract the request encryption key
    let req_enc_key = todo!("extract encryption key");

    // // actually get the SnapSync data
    // let response_body: SnapSyncResponse = build_snapsync_response(req_enc_key);

    // return the response
    let response_json = serde_json::to_string("&response_body").unwrap();
    // let response_json = serde_json::to_string(&response_body).unwrap();
    Ok(Response::new(Body::from(response_json)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::attest_signing_key;
    use hyper::{Body, Request, Response, StatusCode};
    use kbs_types::Tee;
    use serial_test::serial;

    use crate::{
        coco_as::handlers::attestation_eval_evidence_handler, coco_as::into_original::*,
        init_as_policies, init_coco_aa, init_coco_as, utils::test_utils::is_sudo,
    };

    #[serial(attestation_agent)]
    #[tokio::test]
    async fn test_snapsync_handler() {
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

        // Get a sample attestation
        let (attestation, rsa_pk_pem) = attest_signing_key().await.unwrap();

        // Make the request
        let snap_sync_request = SnapSyncRequest {
            client_attestation: attestation,
            tee: Tee::AzTdxVtpm,
            rsa_pk_pem: rsa_pk_pem,
            policy_ids: vec!["allow".to_string()],
        };

        let payload_json = serde_json::to_string(&snap_sync_request).unwrap();

        let req = Request::builder()
            .method("POST")
            .uri("/")
            .body(Body::from(payload_json))
            .unwrap();
        let res: Response<Body> = provide_snapsync_handler(req).await.unwrap();

        let status = res.status();
        let body_bytes = hyper::body::to_bytes(res.into_body()).await.unwrap();
        let body_str = String::from_utf8_lossy(&body_bytes);
        println!("{}", body_str);
        assert_eq!(status, StatusCode::OK);

        // let body_bytes = hyper::body::to_bytes(res.into_body()).await.unwrap();
        // let genesis_data_response: GenesisDataResponse =
        //     serde_json::from_slice(&body_bytes).unwrap();
    }
}
