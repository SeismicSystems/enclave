use attestation_service::HashAlgorithm;
use http_body_util::{BodyExt, Full};
use hyper::{
    body::{Body, Bytes},
    Request, Response,
};
use jsonrpsee::core::RpcResult;
use sha2::{Digest, Sha256};

use super::build_snapsync_response;
use crate::coco_as::eval_att_evidence;
use seismic_enclave::{
    errors::{
        bad_argument_response, bad_evidence_response, invalid_json_body_resp, invalid_req_body_resp,
    },
    rpc_bad_evidence_error,
};
use seismic_enclave::{request_types::snapsync::*, rpc_bad_argument_error};

/// handles a request to provide private information required for SnapSync
///
/// /// # Arguments
/// * `req` - The incoming HTTP request containing the message to be signed. The body of the request
///   Should be a JSON-encoded `SnapSyncRequest`.
///
/// # Returns
/// A `Result` containing an HTTP response with the signature, or an error of type `Infallible`.
/// The response body is JSON-encoded and contains the SnapSyncResponse
/// holding the encrypted data and signature.
///
/// # Errors
/// The function may panic if parsing the request body or signing the message fails.
pub async fn provide_snapsync_handler(
    req: Request<impl Body>,
) -> Result<Response<Full<Bytes>>, anyhow::Error> {
    // parse the request body
    let body_bytes: Bytes = match req.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return Ok(invalid_req_body_resp()),
    };

    // Deserialize the request body into the appropriate struct
    let snapsync_request: SnapSyncRequest = match serde_json::from_slice(&body_bytes) {
        Ok(request) => request,
        Err(_) => {
            return Ok(invalid_json_body_resp());
        }
    };

    // verify the request attestation
    let signing_pk_hash: [u8; 32] =
        Sha256::digest(snapsync_request.client_signing_pk.as_slice()).into();
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
    let client_signing_pk =
        match secp256k1::PublicKey::from_slice(&snapsync_request.client_signing_pk) {
            Ok(pk) => pk,
            Err(_) => {
                return Ok(bad_argument_response(anyhow::anyhow!(
                    "Unable to deserialize the client signing public key"
                )))
            }
        };
    let response_body: SnapSyncResponse = build_snapsync_response(client_signing_pk).await.unwrap();

    // return the response
    let response_json = serde_json::to_string(&response_body).unwrap();
    Ok(Response::new(Full::new(Bytes::from(response_json))))
}

/// handles a request to provide private information required for SnapSync
///
/// /// # Arguments
/// * `req` - The incoming HTTP request containing the message to be signed. The body of the request
///   Should be a JSON-encoded `SnapSyncRequest`.
///
/// # Returns
/// A `Result` containing an HTTP response with the signature, or an error of type `Infallible`.
/// The response body is JSON-encoded and contains the SnapSyncResponse
/// holding the encrypted data and signature.
///
/// # Errors
/// The function may panic if parsing the request body or signing the message fails.
pub async fn rpc_provide_snapsync_handler(request: SnapSyncRequest) -> RpcResult<SnapSyncResponse> {
    // verify the request attestation
    let signing_pk_hash: [u8; 32] = Sha256::digest(request.client_signing_pk.as_slice()).into();
    let eval_result = eval_att_evidence(
        request.client_attestation,
        request.tee,
        Some(attestation_service::Data::Raw(signing_pk_hash.to_vec())),
        HashAlgorithm::Sha256,
        None,
        HashAlgorithm::Sha256,
        request.policy_ids,
    )
    .await;

    match eval_result {
        Ok(_) => (),
        Err(e) => {
            return Err(rpc_bad_evidence_error(e));
        }
    };

    // Get the SnapSync data
    let client_signing_pk = match secp256k1::PublicKey::from_slice(&request.client_signing_pk) {
        Ok(pk) => pk,
        Err(_) => {
            return Err(rpc_bad_argument_error(anyhow::anyhow!(
                "Unable to deserialize the client signing public key"
            )));
        }
    };
    let response_body: SnapSyncResponse = build_snapsync_response(client_signing_pk).await.unwrap();

    // return the response
    Ok(response_body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::get_secp256k1_sk;

    use hyper::StatusCode;
    use kbs_types::Tee;
    use secp256k1::ecdh::SharedSecret;
    use seismic_enclave::aes_decrypt;
    use seismic_enclave::derive_aes_key;
    use seismic_enclave::secp256k1_verify;
    use serial_test::serial;

    use crate::{
        coco_aa::attest_signing_pk,
        // coco_as::handlers::attestation_eval_evidence_handler, coco_as::into_original::*,
        init_as_policies,
        init_coco_aa,
        init_coco_as,
        utils::test_utils::is_sudo,
    };

    #[serial(attestation_agent, attestation_service)]
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

        let req: Request<Full<Bytes>> = Request::builder()
            .method("POST")
            .uri("/")
            .body(Full::from(Bytes::from(payload_json)))
            .unwrap();
        let res: Response<Full<Bytes>> = provide_snapsync_handler(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK, "{res:?}");

        let body: Bytes = res.into_body().collect().await.unwrap().to_bytes();
        let snapsync_response: SnapSyncResponse = serde_json::from_slice(&body).unwrap();

        // Check that you can decrypt the response successfully
        let server_pk =
            secp256k1::PublicKey::from_slice(&snapsync_response.server_signing_pk).unwrap();
        let shared_secret = SharedSecret::new(&server_pk, &client_sk);
        let aes_key = derive_aes_key(&shared_secret).unwrap();
        let decrypted_bytes: Vec<u8> = aes_decrypt(
            &aes_key,
            &snapsync_response.encrypted_data,
            snapsync_response.nonce,
        )
        .unwrap();
        let _: SnapSyncData = SnapSyncData::from_bytes(&decrypted_bytes).unwrap();

        // Check that the signature is valid
        let verified = secp256k1_verify(
            &snapsync_response.encrypted_data,
            &snapsync_response.signature,
            server_pk,
        )
        .expect("Internal error while verifying the signature");
        assert!(verified);
    }

    // test that it rejects a bad attestation (ex wrong public key)
    #[tokio::test]
    #[serial(attestation_service, attestation_agent)]
    async fn test_snapsync_handler_pk_mismatch() {
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
        let mut wrong_pk = client_signing_pk.clone();
        wrong_pk[0] = !wrong_pk[0];

        // Make the request
        let snap_sync_request = SnapSyncRequest {
            client_attestation: attestation,
            client_signing_pk: wrong_pk,
            tee: Tee::AzTdxVtpm,
            policy_ids: vec!["allow".to_string()],
        };

        let payload_json = serde_json::to_string(&snap_sync_request).unwrap();
        let req: Request<Full<Bytes>> = Request::builder()
            .method("POST")
            .uri("/")
            .body(Full::from(Bytes::from(payload_json)))
            .unwrap();
        let res: Response<Full<Bytes>> = provide_snapsync_handler(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }
}
