use http_body_util::{BodyExt, Full};
use hyper::{
    body::{Body, Bytes},
    Request, Response,
};
use jsonrpsee::core::RpcResult;

use super::{enclave_sign, get_secp256k1_pk};
use seismic_enclave::errors::{invalid_json_body_resp, invalid_req_body_resp};
use seismic_enclave::request_types::signing::*;
use seismic_enclave::{crypto::*, rpc_bad_argument_error};

/// Handles request to sign a message using secp256k1.
///
/// # Arguments
/// * `req` - The incoming HTTP request containing the message to be signed. The body of the request
///   Should be a JSON-encoded `Secp256k1SignRequest`.
///
/// # Returns
/// A `Result` containing an HTTP response with the signature, or an error of type `Infallible`.
/// The response body is JSON-encoded and contains the signature as part of a `Secp256k1SignResponse`.
///
/// # Errors
/// The function may panic if parsing the request body or signing the message fails.
pub async fn rpc_secp256k1_sign_handler(
    request: Secp256k1SignRequest,
) -> RpcResult<Secp256k1SignResponse> {
    // sign the message
    let signature = enclave_sign(&request.msg).map_err(|e| rpc_bad_argument_error(e))?;
    Ok(Secp256k1SignResponse { sig: signature })
}

/// Handles request to verify a secp256k1 signature.
///
/// # Arguments
/// * `req` - The incoming HTTP request containing the message and signature to verify. The body of the request
///   Should be a JSON-encoded `Secp256k1VerifyRequest`.
///
/// # Returns
/// A `Result` containing an HTTP response with the verification result, or an error of type `Infallible`.
/// The response body is JSON-encoded and contains the verification result as part of a `Secp256k1VerifyResponse`.
///
/// # Errors
/// The function may panic if parsing the request body or verifying the signature fails.
pub async fn rpc_secp256k1_verify_handler(
    request: Secp256k1VerifyRequest,
) -> RpcResult<Secp256k1VerifyResponse> {
    // verify the signature
    let pk = get_secp256k1_pk();
    let verified = secp256k1_verify(&request.msg, &request.sig, pk)
        .map_err(|e| rpc_bad_argument_error(anyhow::anyhow!(e)))?;

    Ok(Secp256k1VerifyResponse { verified })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::Request;

    #[tokio::test]
    async fn test_secp256k1_sign() {
        // Prepare sign request body
        let msg_to_sign: Vec<u8> = vec![84, 101, 115, 116, 32, 77, 101, 115, 115, 97, 103, 101]; // "Test Message"
        let sign_request = Secp256k1SignRequest {
            msg: msg_to_sign.clone(),
        };

        let res = rpc_secp256k1_sign_handler(sign_request).await.unwrap();
        assert!(!res.sig.is_empty());
    }

    #[tokio::test]
    async fn test_secp256k1_verify() {
        // Prepare sign request to get a valid signature
        let msg_to_sign: Vec<u8> = vec![84, 101, 115, 116, 32, 77, 101, 115, 115, 97, 103, 101]; // "Test Message"
        let sign_request = Secp256k1SignRequest {
            msg: msg_to_sign.clone(),
        };
        let sign_payload_json = serde_json::to_string(&sign_request).unwrap();
        let res = rpc_secp256k1_sign_handler(sign_request).await.unwrap();

        // Prepare verify request body
        let verify_request = Secp256k1VerifyRequest {
            msg: msg_to_sign,
            sig: res.sig,
        };

        let res = rpc_secp256k1_verify_handler(verify_request).await.unwrap();
        assert_eq!(res.verified, true);
    }
}
