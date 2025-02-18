use attestation_service::HashAlgorithm;
use jsonrpsee::core::RpcResult;
use sha2::{Digest, Sha256};

use super::build_snapsync_response;
use crate::coco_as::eval_att_evidence;
use seismic_enclave::rpc_bad_evidence_error;
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
pub async fn provide_snapsync_handler(request: SnapSyncRequest) -> RpcResult<SnapSyncResponse> {
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

    use kbs_types::Tee;
    use secp256k1::ecdh::SharedSecret;
    use seismic_enclave::aes_decrypt;
    use seismic_enclave::derive_aes_key;
    use seismic_enclave::secp256k1_verify;
    use serial_test::serial;

    use crate::{
        coco_aa::attest_signing_pk, coco_aa::init_coco_aa, coco_as::init_as_policies,
        coco_as::init_coco_as, utils::test_utils::is_sudo,
    };

    #[serial(attestation_agent, attestation_service)]
    #[tokio::test]
    async fn test_snapsync_handler() {
        // handle set up permissions
        if !is_sudo() {
            panic!("test_eval_evidence_az_tdx: skipped (requires sudo privileges)");
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

        let snapsync_response = provide_snapsync_handler(snap_sync_request).await.unwrap();

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
            panic!("test_eval_evidence_az_tdx: skipped (requires sudo privileges)");
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

        let res = provide_snapsync_handler(snap_sync_request).await;
        assert_eq!(res.is_err(), true);
        let err = res.err().unwrap();
        assert!(err.to_string().contains("Error while evaluating evidence"));
    }
}
