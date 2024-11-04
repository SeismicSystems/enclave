//! This module provides a client for interacting with a TEE Service server.
//!
//! The TEE client makes HTTP requests to a TEE server to perform
//! operations, e.g. encryption and decryption operations. The main structures and
//! traits define the API and implementation for the TEE client.
#![allow(async_fn_in_trait)]
pub mod http_client;
pub mod mock_server;

use crate::request_types::{
    coco_aa::*,
    coco_as::*,
    genesis::*,
    signing::*,
    tx_io::*
};

/// Trait for the API of the TEE client
pub trait TeeAPI {
    // Gets the genesis data for the chain
    async fn genesis_data(
        &self,
        payload: GenesisData,
    ) -> Result<GenesisDataResponse, anyhow::Error>;
    
    // Gets an attestation for the requested data
    async fn attestation_get_evidence(
        &self,
        payload: AttestationGetEvidenceRequest,
    ) -> Result<AttestationGetEvidenceResponse, anyhow::Error>;

    // Evaluates an attestation evidence
    async fn attestation_eval_evidence(
        &self,
        payload: AttestationEvalEvidenceRequest,
    ) -> Result<AttestationEvalEvidenceResponse, anyhow::Error>;

    // signs the requested data with a secp256k1 key
    async fn signing_sign(
        &self,
        payload: Secp256k1SignRequest,
    ) -> Result<Secp256k1SignResponse, anyhow::Error>;

    // verifies the signed data with a secp256k1 key
    async fn signing_verify(
        &self,
        payload: Secp256k1VerifyRequest,
    ) -> Result<Secp256k1VerifyResponse, anyhow::Error>;

    /// Encrypts the given data using the public key included in the request
    /// and the private key of the TEE server
    async fn tx_io_encrypt(
        &self,
        payload: IoEncryptionRequest,
    ) -> Result<IoEncryptionResponse, anyhow::Error>;

    /// Decrypts the given data using the public key included in the request
    /// and the private key of the TEE server
    async fn tx_io_decrypt(
        &self,
        payload: IoDecryptionRequest,
    ) -> Result<IoDecryptionResponse, anyhow::Error>;


}

pub trait WalletAPI {
    fn encrypt(
        &self,
        data: &Vec<u8>,
        nonce: u64,
        private_key: &secp256k1::SecretKey,
    ) -> Result<Vec<u8>, anyhow::Error>;
}
