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
    /// network root key it does not yet hold from an existing node. The
    /// responder verifies `request.evidence` and appraises the requester's
    /// measurements before wrapping anything; see [`RootKeyRequest`] and
    /// [`RootKeyResponse`] for the transcript each side attests.
    #[method(name = "getWrappedRootKey")]
    async fn get_wrapped_root_key(&self, request: RootKeyRequest) -> RpcResult<RootKeyResponse>;
}

/// The requester's half of the root-key bootstrap handshake: a fresh nonce and
/// ephemeral pubkey, attested by `evidence` over
/// [`root_key_request_binding`](seismic_attestation::bindings::root_key_request_binding).
///
/// The ephemeral key travels as a `secp256k1::PublicKey` (compressed on the
/// wire); the binding helpers consume its 33-byte SEC1 form via `.serialize()`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RootKeyRequest {
    /// Requester-fresh replay protection, bound into both quotes.
    pub nonce_b: [u8; 32],
    /// Requester ephemeral ECDH pubkey; the matching secret stays in the
    /// requester's custodian.
    pub eph_pk_b: secp256k1::PublicKey,
    /// Requester attestation over `root_key_request_binding(network_id,
    /// nonce_b, eph_pk_b)`.
    pub evidence: AttestationExchangeMessage,
}

/// The responder's half of the root-key bootstrap handshake: its ephemeral
/// pubkey, the AEAD-wrapped root key, and its attestation over
/// [`root_key_response_binding`](seismic_attestation::bindings::root_key_response_binding).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RootKeyResponse {
    /// Responder ephemeral ECDH pubkey.
    pub eph_pk_a: secp256k1::PublicKey,
    /// `nonce(12) || AES-256-GCM(root_key)`, as produced by
    /// `seismic_custodian::Custodian::wrap_root_key_for_peer`.
    pub wrapped: Vec<u8>,
    /// Responder attestation over `root_key_response_binding(network_id,
    /// nonce_b, eph_pk_a, wrapped)`.
    pub evidence: AttestationExchangeMessage,
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
