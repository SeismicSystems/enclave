use hyper::{body::to_bytes, Body, Request, Response};
use std::convert::Infallible;

use crate::signing::structs::*;
use crate::utils::crypto_utils::*;

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
pub async fn secp256k1_sign_handler(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    // parse the request body
    let body_bytes = to_bytes(req.into_body()).await.unwrap();
    let sign_request: Secp256k1SignRequest = serde_json::from_slice(&body_bytes).unwrap();

    // sign the message
    let sk = get_secp256k1_sk();
    let signature = secp256k1_sign_digest(&sign_request.msg, sk).unwrap();

    let response_body = Secp256k1SignResponse { sig: signature };
    let response_json = serde_json::to_string(&response_body).unwrap();

    Ok(Response::new(Body::from(response_json)))
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
pub async fn secp256k1_verify_handler(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    // parse the request body
    let body_bytes = to_bytes(req.into_body()).await.unwrap();
    let verify_request: Secp256k1VerifyRequest = serde_json::from_slice(&body_bytes).unwrap();

    // verify the signature
    let pk = get_secp256k1_pk();
    let verified = secp256k1_verify(&verify_request.msg, &verify_request.sig, pk).unwrap();

    let response_body = Secp256k1VerifyResponse { verified };
    let response_json = serde_json::to_string(&response_body).unwrap();

    Ok(Response::new(Body::from(response_json)))
}

/// Loads a secp256k1 private key from a file.
///
/// This function reads the keypair from a JSON file for testing purposes. Eventually, it should
/// be replaced with a more secure solution, such as requesting a key from a KMS service.
///
/// # Returns
/// A secp256k1 `SecretKey` loaded from the keypair file.
///
/// # Panics
/// The function may panic if the file is missing or if it cannot deserialize the keypair.
fn get_secp256k1_sk() -> secp256k1::SecretKey {
    get_sample_secp256k1_sk()
}

/// Loads a secp256k1 public key from a file.
///
/// This function reads the keypair from a JSON file for testing purposes. Eventually, it should
/// be replaced with a more secure solution, such as requesting a key from a KMS service.
///
/// # Returns
/// A secp256k1 `PublicKey` loaded from the keypair file.
///
/// # Panics
/// The function may panic if the file is missing or if it cannot deserialize the keypair.
fn get_secp256k1_pk() -> secp256k1::PublicKey {
    get_sample_secp256k1_pk()
}
