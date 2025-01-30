//! This module provides a client for interacting with a TEE Service server.
//!
//! The TEE client makes HTTP requests to a TEE server to perform
//! operations, e.g. encryption and decryption operations. The main structures and
//! traits define the API and implementation for the TEE client.
#![allow(async_fn_in_trait)]
pub mod http_client;
pub mod mock_server;

use crate::{
    nonce::Nonce,
    request_types::{coco_aa::*, coco_as::*, genesis::*, signing::*, tx_io::*},
};

use schnorrkel::keys::Keypair as SchnorrkelKeypair;

pub trait TeeAPI {
    async fn genesis_data(
        &self,
        _payload: GenesisData,
    ) -> Result<GenesisDataResponse, anyhow::Error> {
        Err(anyhow::Error::msg("Unimplemented"))
    }

    async fn attestation_get_evidence(
        &self,
        _payload: AttestationGetEvidenceRequest,
    ) -> Result<AttestationGetEvidenceResponse, anyhow::Error> {
        Err(anyhow::Error::msg("Unimplemented"))
    }

    async fn attestation_eval_evidence(
        &self,
        _payload: AttestationEvalEvidenceRequest,
    ) -> Result<AttestationEvalEvidenceResponse, anyhow::Error> {
        Err(anyhow::Error::msg("Unimplemented"))
    }

    async fn signing_sign(
        &self,
        _payload: Secp256k1SignRequest,
    ) -> Result<Secp256k1SignResponse, anyhow::Error> {
        Err(anyhow::Error::msg("Unimplemented"))
    }

    async fn signing_verify(
        &self,
        _payload: Secp256k1VerifyRequest,
    ) -> Result<Secp256k1VerifyResponse, anyhow::Error> {
        Err(anyhow::Error::msg("Unimplemented"))
    }

    async fn tx_io_encrypt(
        &self,
        _payload: IoEncryptionRequest,
    ) -> Result<IoEncryptionResponse, anyhow::Error> {
        Err(anyhow::Error::msg("Unimplemented"))
    }

    async fn tx_io_decrypt(
        &self,
        _payload: IoDecryptionRequest,
    ) -> Result<IoDecryptionResponse, anyhow::Error> {
        Err(anyhow::Error::msg("Unimplemented"))
    }

    async fn get_eph_rng_keypair(
        &self,
    ) -> Result<SchnorrkelKeypair, anyhow::Error> {
        Err(anyhow::Error::msg("Unimplemented"))
    }
}

pub trait WalletAPI {
    fn encrypt(
        &self,
        data: Vec<u8>,
        nonce: impl Into<Nonce>,
        private_key: &secp256k1::SecretKey,
    ) -> Result<Vec<u8>, anyhow::Error>;

    fn decrypt(
        &self,
        data: Vec<u8>,
        nonce: impl Into<Nonce>,
        private_key: &secp256k1::SecretKey,
    ) -> Result<Vec<u8>, anyhow::Error>;
}
