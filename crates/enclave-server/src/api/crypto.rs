use jsonrpsee::core::{async_trait, RpcResult};
use log::error;
use secp256k1::PublicKey;
use seismic_enclave::signing::{Secp256k1SignRequest, Secp256k1SignResponse, Secp256k1VerifyRequest, Secp256k1VerifyResponse};
use seismic_enclave::tx_io::{IoDecryptionRequest, IoDecryptionResponse, IoEncryptionRequest, IoEncryptionResponse};
use seismic_enclave::{ecdh_encrypt, get_unsecure_sample_secp256k1_pk, secp256k1_verify, get_unsecure_sample_secp256k1_sk};

use crate::api::traits::CryptoApi;
use crate::api::error::{rpc_bad_argument_error, rpc_invalid_ciphertext_error};
use crate::key_manager::NetworkKeyProvider;
use crate::signing::enclave_sign;

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
        let signature = secp256k1_sign_digest(data, sk)
            .map_err(|e| anyhow!("Internal Error while signing the message: {:?}", e))?;
        Ok(Secp256k1SignResponse { sig: signature })
    }

    async fn secp256k1_verify(
        &self,
        kp: &dyn NetworkKeyProvider,
        req: Secp256k1VerifyRequest,
    ) -> RpcResult<Secp256k1VerifyResponse> {
        let verified = secp256k1_verify(&req.msg, &req.sig, kp.get_tx_io_pk())
            .map_err(|e| rpc_bad_argument_error(anyhow::anyhow!(e)))?;
        
        Ok(Secp256k1VerifyResponse { verified })
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
        Ok(self.kp.get_rng_keypair())
    }
}
