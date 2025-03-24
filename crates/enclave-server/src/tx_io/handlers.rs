use crate::key_manager::NetworkKeyProvider;
use seismic_enclave::request_types::tx_io::*;
use seismic_enclave::rpc_bad_argument_error;
use seismic_enclave::{
    crypto::{ecdh_decrypt, ecdh_encrypt},
    rpc_invalid_ciphertext_error,
};

use jsonrpsee::core::RpcResult;
use tracing::error;

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
    req: IoEncryptionRequest,
    kp: &dyn NetworkKeyProvider,
) -> RpcResult<IoEncryptionResponse> {
    // load key and encrypt data
    let encrypted_data = match ecdh_encrypt(&req.key, &kp.get_tx_io_sk(), &req.data, req.nonce)
    {
        Ok(data) => data,
        Err(e) => {
            error!("Failed to encrypt data: {}", e);
            return Err(rpc_bad_argument_error(e));
        }
    };

    Ok(IoEncryptionResponse { encrypted_data })
}

/// Handles an IO decryption request, decrypting the provided encrypted data using AES.
///
/// # Arguments
/// * `req` - The incoming HTTP request containing the encrypted data. The body of the request
///   Should be a JSON-encoded `IoDecryptionRequest`.
///
/// # Returns
/// A `Result` containing an HTTP response with the decrypted data, or an error of type `Infallible`.  /// The response body is JSON-encoded and contains the decrypted data as part of an `IoDecryptionResponse`.
///
/// # Errors
/// The function may panic if parsing the request body, creating the shared secret, or decrypting the data fails.
pub async fn tx_io_decrypt_handler(
    request: IoDecryptionRequest,
    kp: &dyn NetworkKeyProvider,
) -> RpcResult<IoDecryptionResponse> {
    // load key and decrypt data
    let decrypted_data = match ecdh_decrypt(
        &request.key,
        &kp.get_tx_io_sk(),
        &request.data,
        request.nonce,
    ) {
        Ok(data) => data,
        Err(e) => {
            error!("Failed to decrypt data: {}", e);
            return Err(rpc_invalid_ciphertext_error(e));
        }
    };

    Ok(IoDecryptionResponse { decrypted_data })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_manager::builder::KeyManagerBuilder;
    use seismic_enclave::{get_unsecure_sample_secp256k1_pk, nonce::Nonce};

    #[tokio::test]
    async fn test_io_encryption() {
        // Prepare encryption request body
        let data_to_encrypt = vec![72, 101, 108, 108, 111];
        let nonce = Nonce::new_rand();
        let req = IoEncryptionRequest {
            key: get_unsecure_sample_secp256k1_pk(),
            data: data_to_encrypt.clone(),
            nonce: nonce.clone().into(),
        };
        let kp = KeyManagerBuilder::build_mock().unwrap();

        let res = tx_io_encrypt_handler(req, &kp).await.unwrap();

        println!("Encrypted data: {:?}", res.encrypted_data);

        // check that decryption returns the original data
        // Prepare decrypt request body
        let req = IoDecryptionRequest {
            key: get_unsecure_sample_secp256k1_pk(),
            data: res.encrypted_data,
            nonce: nonce.clone(),
        };

        let res = tx_io_decrypt_handler(req, &kp).await.unwrap();

        println!("Decrypted data: {:?}", res.decrypted_data);

        assert_eq!(res.decrypted_data, data_to_encrypt);
    }

    #[tokio::test]
    async fn test_decrypt_invalid_ciphertext() {
        let bad_ciphertext = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let nonce = Nonce::new_rand();
        let decryption_request = IoDecryptionRequest {
            key: get_unsecure_sample_secp256k1_pk(),
            data: bad_ciphertext,
            nonce: nonce.clone(),
        };
        let kp = KeyManagerBuilder::build_mock().unwrap();
        let res = tx_io_decrypt_handler(decryption_request, &kp).await;

        assert_eq!(res.is_err(), true);
        assert_eq!(
            res.err()
                .unwrap()
                .to_string()
                .contains("Invalid ciphertext"),
            true
        );
    }
}
