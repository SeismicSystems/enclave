use attestation_service::HashAlgorithm;
use hyper::{body::to_bytes, Body, Request, Response};
use sha2::{Digest, Sha256};
use std::convert::Infallible;

use super::build_snapsync_response;
use crate::coco_as::eval_att_evidence;
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
    let signing_pk_hash: [u8; 32] = Sha256::digest(snapsync_request.client_signing_pk.as_slice()).into();
    let eval_result = eval_att_evidence(
        snapsync_request.client_attestation,
        snapsync_request.tee,
        Some(attestation_service::Data::Raw(signing_pk_hash.to_vec())),
        HashAlgorithm::Sha256,
        None,
        HashAlgorithm::Sha256,
        snapsync_request.policy_ids,
    )
    .await;

    match eval_result {
        Ok(_) => (),
        Err(e) => {
            return Ok(bad_evidence_response(e));
        }
    };

    // Get the SnapSync data
    let client_signing_pk = secp256k1::PublicKey::from_slice(
        &snapsync_request.client_signing_pk
    ).expect("Internal error while deserializing the public key");
    let response_body: SnapSyncResponse = build_snapsync_response(client_signing_pk).await.unwrap();

    // return the response
    let response_json = serde_json::to_string(&response_body).unwrap();
    Ok(Response::new(Body::from(response_json)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::{Body, Request, Response, StatusCode};
    use kbs_types::Tee;
    use secp256k1::ecdh::SharedSecret;
    use serial_test::serial;
    use crate::get_secp256k1_sk;
    use tee_service_api::derive_aes_key;
    use tee_service_api::aes_decrypt;
    use tee_service_api::secp256k1_verify;

    use crate::{
        // coco_as::handlers::attestation_eval_evidence_handler, coco_as::into_original::*,
        init_as_policies, init_coco_aa, init_coco_as, utils::test_utils::is_sudo,
        coco_aa::attest_signing_pk,
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

        // Get sample attestation and keys to make the test request
        let client_sk = get_secp256k1_sk();
        let (attestation, signing_pk) = attest_signing_pk().await.unwrap();
        let client_signing_pk = signing_pk.serialize().to_vec();

        // Make the request
        let snap_sync_request = SnapSyncRequest {
            client_attestation: attestation,
            client_signing_pk,
            tee: Tee::AzTdxVtpm,
            policy_ids: vec!["allow".to_string()],
        };

        let payload_json = serde_json::to_string(&snap_sync_request).unwrap();

        let req = Request::builder()
            .method("POST")
            .uri("/")
            .body(Body::from(payload_json))
            .unwrap();
        let res: Response<Body> = provide_snapsync_handler(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        println!("response returned success");

        let body_bytes = hyper::body::to_bytes(res.into_body()).await.unwrap();
        let snapsync_response: SnapSyncResponse =
            serde_json::from_slice(&body_bytes).unwrap();

        // Check that you can decrypt the response successfully
        let server_pk = secp256k1::PublicKey::from_slice(&snapsync_response.server_signing_pk).unwrap();
        let shared_secret = SharedSecret::new(&server_pk, &client_sk);
        let aes_key = derive_aes_key(&shared_secret).unwrap();
        let decrypted_bytes: Vec<u8>  = aes_decrypt(&aes_key, &snapsync_response.encrypted_data, snapsync_response.nonce).unwrap();
        let _: SnapSyncData = SnapSyncData::from_bytes(&decrypted_bytes);
        
        // Check that the signature is valid
        let verified = secp256k1_verify(&snapsync_response.encrypted_data, &snapsync_response.signature, server_pk)
            .expect("Internal error while verifying the signature");
        assert!(verified);
    }
}
