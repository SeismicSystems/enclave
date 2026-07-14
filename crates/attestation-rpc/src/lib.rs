//! Purpose-specific JSON-RPC APIs for Seismic attestation evidence.
//!
//! This crate keeps attestation RPC types separate from the general
//! `seismic-enclave` key-operation facade, so consumers such as reth can build
//! the key APIs without platform-attestation dependencies.

use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use serde::{Deserialize, Serialize};

pub use secp256k1;
pub use seismic_attestation::AttestationExchangeMessage;

/// Network-facing attestation evidence methods.
///
/// Each method derives a purpose-specific evidence binding from its request
/// inputs and the measured service's local state.
#[rpc(client, server)]
pub trait AttestationRpc {
    /// Attest this node's tx-io public key for `epoch`.
    ///
    /// The service derives `tx_io_binding(own_network_id, own_tx_io_pk, epoch)`.
    #[method(name = "getTxIoAttestationEvidence")]
    async fn get_tx_io_attestation_evidence(
        &self,
        epoch: u64,
    ) -> RpcResult<TxIoAttestationResponse>;

    /// Return the network root key wrapped to an attested booting peer.
    ///
    /// The bodies remain opaque until `RootKeyRequest` and `RootKeyResponse`
    /// move into the planned bootstrap protocol crate. Keeping them opaque
    /// here preserves the existing wire format without creating a dependency
    /// on the enclave-server implementation.
    #[method(name = "getWrappedRootKey")]
    async fn get_wrapped_root_key(&self, request: Vec<u8>) -> RpcResult<Vec<u8>>;
}

/// Complete evidence needed by a relying client to authenticate a tx-io key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxIoAttestationResponse {
    /// The key claimed by, and bound into, `evidence`.
    pub tx_io_pk: secp256k1::PublicKey,
    /// The requested tx-io key epoch.
    pub epoch: u64,
    /// Complete backend evidence envelope. The relying client must verify this
    /// itself against its expected network, key, epoch, and measurement policy.
    pub evidence: AttestationExchangeMessage,
}
