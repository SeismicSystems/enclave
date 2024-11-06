use attestation_service::HashAlgorithm;
use hyper::{body::to_bytes, Body, Request, Response};
use sha2::{Digest, Sha256};
use std::convert::Infallible;
use openssl::pkey::Public;
use openssl::rsa::Rsa;

use super::build_snapsync_response;
use crate::coco_as::eval_att_evidence;
use tee_service_api::errors::{
    bad_evidence_response, invalid_json_body_resp, invalid_req_body_resp,
};
use tee_service_api::request_types::snapsync::*;
use tee_service_api::secp256k1_verify;

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

    // verify the rsa_pk_pem signature
    let client_signing_pk = secp256k1::PublicKey::from_slice(
        &snapsync_request.client_signing_pk
    ).expect("Internal error while deserializing the public key");

    let verified = secp256k1_verify(
        &snapsync_request.rsa_pk_pem, 
        &snapsync_request.rsa_pk_pem_sig, 
        client_signing_pk,
    ).expect("Internal error while verifying the signature");

    if !verified {
        // TODO: return a different error response
        return Ok(bad_evidence_response(anyhow::anyhow!("Invalid signature")));
    }

    // Get the SnapSync data
    let rsa: Rsa<Public> = Rsa::public_key_from_pem(snapsync_request.rsa_pk_pem.as_slice()).unwrap();
    let response_body: SnapSyncResponse = build_snapsync_response(rsa).await.unwrap();

    // return the response
    let response_json = serde_json::to_string(&response_body).unwrap();
    // let response_json = serde_json::to_string(&response_body).unwrap();
    Ok(Response::new(Body::from(response_json)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::{Body, Request, Response, StatusCode};
    use kbs_types::Tee;
    use serial_test::serial;
    use tee_service_api::get_sample_rsa;
    use tee_service_api::get_sample_secp256k1_sk;
    use tee_service_api::secp256k1_sign_digest;

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
        let (attestation, signing_pk) = attest_signing_pk().await.unwrap();
        let client_signing_pk = signing_pk.serialize().to_vec();
        let sample_rsa = get_sample_rsa();
        let rsa_pk_pem = sample_rsa.public_key_to_pem().unwrap();
        let rsa_pk_pem_sig = secp256k1_sign_digest(&rsa_pk_pem, get_sample_secp256k1_sk()).expect("Internal Error while signing the message");


        // Make the request
        let snap_sync_request = SnapSyncRequest {
            client_attestation: attestation,
            client_signing_pk,
            tee: Tee::AzTdxVtpm,
            rsa_pk_pem,
            rsa_pk_pem_sig,
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
