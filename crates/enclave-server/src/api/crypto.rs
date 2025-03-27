use anyhow::anyhow;
use jsonrpsee::core::{async_trait, RpcResult};
use log::error;
use secp256k1::PublicKey;
use seismic_enclave::signing::{Secp256k1SignRequest, Secp256k1SignResponse, Secp256k1VerifyRequest, Secp256k1VerifyResponse};
use seismic_enclave::tx_io::{IoDecryptionRequest, IoDecryptionResponse, IoEncryptionRequest, IoEncryptionResponse};
use seismic_enclave::{ecdh_decrypt, ecdh_encrypt, rpc_bad_argument_error, rpc_invalid_ciphertext_error, secp256k1_sign_digest, secp256k1_verify};

use crate::api::traits::CryptoApi;
use crate::key_manager::NetworkKeyProvider;

/// Implementation of cryptographic operations API
pub struct CryptoService;

#[async_trait]
impl CryptoApi for CryptoService {
    async fn get_public_key(&self, kp: &dyn NetworkKeyProvider) -> RpcResult<PublicKey> {
        Ok(kp.get_tx_io_pk())
    }

    async fn secp256k1_sign(
        &self,
        kp: &dyn NetworkKeyProvider,
        req: Secp256k1SignRequest,
    ) -> RpcResult<Secp256k1SignResponse> {
        let sk = kp.get_tx_io_sk();
        let signature = secp256k1_sign_digest(&req.msg, sk)
            .map_err(|e| rpc_bad_argument_error(anyhow::anyhow!(e)))?;
        Ok(Secp256k1SignResponse { sig: signature })
    }

    async fn encrypt(
        &self,
        kp: &dyn NetworkKeyProvider,
        req: IoEncryptionRequest,
    ) -> RpcResult<IoEncryptionResponse> {
        let encrypted_data = match ecdh_encrypt(&req.key, &kp.get_tx_io_sk(), &req.data, req.nonce) {
            Ok(data) => data,
            Err(e) => {
                error!("Failed to encrypt data: {}", e);
                return Err(rpc_bad_argument_error(e));
            }
        };
        
        Ok(IoEncryptionResponse { encrypted_data })
    }

    async fn decrypt(
        &self,
        kp: &dyn NetworkKeyProvider,
        req: IoDecryptionRequest,
    ) -> RpcResult<IoDecryptionResponse> {
        let decrypted_data = match ecdh_decrypt(
            &req.key,
            &kp.get_tx_io_sk(),
            &req.data,
            req.nonce,
        ) {
            Ok(data) => data,
            Err(e) => {
                error!("Failed to decrypt data: {}", e);
                return Err(rpc_invalid_ciphertext_error(e));
            }
        };
        
        Ok(IoDecryptionResponse { decrypted_data })
    }
    
    async fn get_eph_rng_keypair(&self, kp: &dyn NetworkKeyProvider) -> RpcResult<schnorrkel::keys::Keypair> {
        Ok(kp.get_rng_keypair())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_manager::builder::KeyManagerBuilder;
    use seismic_enclave::{Nonce, get_unsecure_sample_secp256k1_pk};

    #[tokio::test]
    async fn test_secp256k1_sign() {
        // Prepare sign request body
        let msg_to_sign: Vec<u8> = vec![84, 101, 115, 116, 32, 77, 101, 115, 115, 97, 103, 101]; // "Test Message"
        let sign_request = Secp256k1SignRequest {
            msg: msg_to_sign.clone(),
        };
        let kp = KeyManagerBuilder::build_mock().unwrap();

        let crypto_service = CryptoService;

        let res = crypto_service.secp256k1_sign(&kp, sign_request).await.unwrap();
        assert!(!res.sig.is_empty());
    }

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

        let crypto_service = CryptoService;
        let res = crypto_service.encrypt(&kp, req).await.unwrap();

        // check that decryption returns the original data
        // Prepare decrypt request body
        let req = IoDecryptionRequest {
            key: get_unsecure_sample_secp256k1_pk(),
            data: res.encrypted_data,
            nonce: nonce.clone(),
        };

        let res = crypto_service.decrypt(&kp, req).await.unwrap();

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
        let crypto_service = CryptoService;
        let res = crypto_service.decrypt(&kp, decryption_request).await;

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
