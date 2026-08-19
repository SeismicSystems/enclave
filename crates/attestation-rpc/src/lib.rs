//! Purpose-specific JSON-RPC APIs for Seismic attestation evidence.
//!
//! This crate keeps attestation RPC types separate from the key-operation
//! crates, so consumers such as reth can build the key APIs without
//! platform-attestation dependencies.

use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use serde::{Deserialize, Serialize};

pub use secp256k1;
pub use seismic_attestation::AttestationExchangeMessage;

/// Network-facing attestation evidence methods.
///
/// Each method derives a purpose-specific evidence binding from its request
/// inputs and the measured service's local state, and serves one kind of
/// relying party, named in its doc.
#[rpc(client, server)]
pub trait AttestationRpc {
    /// Attest this node's tx-io public key for `epoch`, for clients
    /// authenticating the network's tx-io key before encrypting a TxSeismic
    /// to it.
    ///
    /// The service derives `tx_io_binding(own_network_id, own_tx_io_pk, epoch)`.
    #[method(name = "getTxIoAttestationEvidence")]
    async fn get_tx_io_attestation_evidence(
        &self,
        epoch: u64,
    ) -> RpcResult<TxIoAttestationResponse>;

    /// Attest this node for an operator verifying a freshly provisioned node
    /// before relying on it — publishing its address, handing it to later
    /// nodes as a bootnode, pointing tooling at it. The check protects only
    /// those operator decisions: membership in the network itself is granted
    /// by the network's own gates (the attested root-key handshake and its
    /// admission policy), never by this check.
    ///
    /// The service derives
    /// `deploy_verification_binding(own_network_id, deployment_nonce)`: the
    /// caller contributes only freshness, and the method answers one fixed
    /// question — a measured node holding the verifier's expected manifest is
    /// live at this endpoint.
    #[method(name = "getDeployVerificationEvidence")]
    async fn get_deploy_verification_evidence(
        &self,
        deployment_nonce: [u8; 32],
    ) -> RpcResult<DeployVerificationResponse>;

    /// Return the network root key wrapped to an attested booting peer.
    ///
    /// The caller is a joining node's own attestation service, acquiring the
    /// network root key it does not yet hold from an existing node.
    ///
    /// The bodies remain opaque until `RootKeyRequest` and `RootKeyResponse`
    /// move into the planned bootstrap protocol crate. Keeping them opaque
    /// here preserves the existing wire format without creating a dependency
    /// on the attestation-service implementation.
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

/// Evidence answering an operator's deploy verification of one candidate node.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeployVerificationResponse {
    /// Complete backend evidence envelope. The verifying operator must
    /// recompute `deploy_verification_binding` from its own manifest's
    /// `network_id` and the `deployment_nonce` it sent, then verify this
    /// envelope against that binding and its measurement policy.
    pub evidence: AttestationExchangeMessage,
}
