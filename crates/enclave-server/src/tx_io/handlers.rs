use http_body_util::{BodyExt, Full};
use hyper::{
    body::{Body, Bytes},
    Request, Response,
};
use jsonrpsee::core::RpcResult;
use seismic_enclave::errors::{
    invalid_ciphertext_resp, invalid_json_body_resp, invalid_req_body_resp,
};
use seismic_enclave::request_types::tx_io::*;
use seismic_enclave::{
    crypto::{ecdh_decrypt, ecdh_encrypt},
    rpc_invalid_ciphertext_error,
};

use crate::get_secp256k1_sk;

/// Handles an IO encryption request, encrypting the provided data using AES.
///
/// # Arguments
/// * `req` - The incoming HTTP request containing the data to be encrypted. The body of the request
///   Should be a JSON-encoded `IoEncryptionRequest`.
///
/// # Returns
/// A `Result` containing an HTTP response with the encrypted data, or an error of type `Infallible`.
/// The response body is JSON-encoded and contains the encrypted data as part of an `IoEncryptionResponse`.
///
/// # Errors
/// The function may panic if parsing the request body, creating the shared secret, or encrypting the data fails.
pub async fn tx_io_encrypt_handler(
    req: Request<impl Body>,
) -> Result<Response<Full<Bytes>>, anyhow::Error> {
    // parse the request body
    let body_bytes: Bytes = match req.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return Ok(invalid_req_body_resp()),
    };

    // Deserialize the request body into IoEncryptionRequest
    let encryption_request: IoEncryptionRequest = match serde_json::from_slice(&body_bytes) {
        Ok(request) => request,
        Err(_) => {
            return Ok(invalid_json_body_resp());
        }
    };

    // load key and encrypt data
    let encrypted_data = ecdh_encrypt(
        &encryption_request.key,
        &get_secp256k1_sk(),
        encryption_request.data,
        encryption_request.nonce,
    )
    .unwrap();

    let response_body = IoEncryptionResponse { encrypted_data };
    let response_json = serde_json::to_string(&response_body).unwrap();

    Ok(Response::new(Full::new(Bytes::from(response_json))))
}

/// Handles an IO decryption request, decrypting the provided encrypted data using AES.
///
/// # Arguments
/// * `req` - The incoming HTTP request containing the encrypted data. The body of the request
///   Should be a JSON-encoded `IoDecryptionRequest`.
///
/// # Returns
/// A `Result` containing an HTTP response with the decrypted data, or an error of type `Infallible`.
/// The response body is JSON-encoded and contains the decrypted data as part of an `IoDecryptionResponse`.
///
/// # Errors
/// The function may panic if parsing the request body, creating the shared secret, or decrypting the data fails.
pub async fn tx_io_decrypt_handler(
    req: Request<impl Body>,
) -> Result<Response<Full<Bytes>>, anyhow::Error> {
    // parse the request body
    let body_bytes: Bytes = match req.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return Ok(invalid_req_body_resp()),
    };

    // Deserialize the request body into IoDecryptionRequest
    let decryption_request: IoDecryptionRequest = match serde_json::from_slice(&body_bytes) {
        Ok(request) => request,
        Err(_) => {
            return Ok(invalid_json_body_resp());
        }
    };

    // load key and decrypt data
    let decrypted_data = ecdh_decrypt(
        &decryption_request.key,
        &get_secp256k1_sk(),
        decryption_request.data,
        decryption_request.nonce,
    );

    let decrypted_data = match decrypted_data {
        Ok(data) => data,
        Err(e) => {
            return Ok(invalid_ciphertext_resp(e));
        }
    };

    let response_body = IoDecryptionResponse { decrypted_data };
    let response_json = serde_json::to_string(&response_body).unwrap();

    Ok(Response::new(Full::new(Bytes::from(response_json))))
}

/// Handles an IO encryption request, encrypting the provided data using AES.
///
/// # Arguments
/// * `req` - The incoming HTTP request containing the data to be encrypted. The body of the request
///   Should be a JSON-encoded `IoEncryptionRequest`.
///
/// # Returns
/// A `Result` containing an HTTP response with the encrypted data, or an error of type `Infallible`.
/// The response body is JSON-encoded and contains the encrypted data as part of an `IoEncryptionResponse`.
///
/// # Errors
/// The function may panic if parsing the request body, creating the shared secret, or encrypting the data fails.
pub async fn rpc_tx_io_encrypt_handler(
    req: IoEncryptionRequest,
) -> RpcResult<IoEncryptionResponse> {
    // load key and encrypt data
    let encrypted_data = ecdh_encrypt(&req.key, &get_secp256k1_sk(), req.data, req.nonce).unwrap();

    Ok(IoEncryptionResponse { encrypted_data })
}

/// Handles an IO decryption request, decrypting the provided encrypted data using AES.
///
/// # Arguments
/// * `req` - The incoming HTTP request containing the encrypted data. The body of the request
///   Should be a JSON-encoded `IoDecryptionRequest`.
///
/// # Returns
/// A `Result` containing an HTTP response with the decrypted data, or an error of type `Infallible`.
/// The response body is JSON-encoded and contains the decrypted data as part of an `IoDecryptionResponse`.
///
/// # Errors
/// The function may panic if parsing the request body, creating the shared secret, or decrypting the data fails.
pub async fn rpc_tx_io_decrypt_handler(
    request: IoDecryptionRequest,
) -> RpcResult<IoDecryptionResponse> {
    // load key and decrypt data
    let decrypted_data = ecdh_decrypt(
        &request.key,
        &get_secp256k1_sk(),
        request.data,
        request.nonce,
    )
    .map_err(|e| rpc_invalid_ciphertext_error(e))?;

    Ok(IoDecryptionResponse { decrypted_data })
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::PublicKey;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_io_encryption() {
        // Prepare encryption request body
        let data_to_encrypt = vec![72, 101, 108, 108, 111];
        let mut nonce = vec![0u8; 4]; // 4 leading zeros
        nonce.extend_from_slice(&(12345678u64).to_be_bytes()); // Append the 8-byte u64
        let req = IoEncryptionRequest {
            key: PublicKey::from_str(
                "03e31e68908a6404a128904579c677534d19d0e5db80c7d9cf4de6b4b7fe0518bd",
            )
            .unwrap(),
            data: data_to_encrypt.clone(),
            nonce: nonce.clone().into(),
        };

        let res = rpc_tx_io_encrypt_handler(req).await.unwrap();

        println!("Encrypted data: {:?}", res.encrypted_data);

        // check that decryption returns the original data
        // Prepare decrypt request body
        let req = IoDecryptionRequest {
            key: PublicKey::from_str(
                "03e31e68908a6404a128904579c677534d19d0e5db80c7d9cf4de6b4b7fe0518bd",
            )
            .unwrap(),
            data: enc_response.encrypted_data,
            nonce: nonce.into(),
        };

        let res = rpc_tx_io_decrypt_handler(req).await.unwrap();

        println!("Decrypted data: {:?}", res.decrypted_data);

        assert_eq!(res.decrypted_data, data_to_encrypt);
    }

    #[tokio::test]
    async fn test_decrypt_invalid_ciphertext() {
        let bad_ciphertext = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let mut nonce = vec![0u8; 4]; // 4 leading zeros
        nonce.extend_from_slice(&(12345678u64).to_be_bytes()); // Append the 8-byte u64
        let decryption_request = IoDecryptionRequest {
            key: PublicKey::from_str(
                "03e31e68908a6404a128904579c677534d19d0e5db80c7d9cf4de6b4b7fe0518bd",
            )
            .unwrap(),
            data: bad_ciphertext,
            nonce: nonce.into(),
        };
        let res = rpc_tx_io_decrypt_handler(decryption_request).await;
        println!("Decryption response: {:?}", res);
    }
}
