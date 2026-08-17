//! The service's JSON-RPC server: this node's network-facing surface.
//!
//! It answers the root-key bootstrap handshake for the nodes joining after
//! this one (gated by [`crate::admission`]), mints tx-io evidence, and serves
//! node status. Startup lives here too, including the wait for this node's own
//! key — see [`crate::join`].

use crate::{
    ATTESTATION_TYPE, Args,
    admission::RegistryAdmission,
    api::{LuksProvisioningStatus, NodeStatusRpcServer},
    bootstrap::{RootKeyRequest, answer_root_key_request},
    join::ensure_root_key_present,
    network::{NETWORK_MANIFEST_PATH, load_manifest},
    rpc_error::{
        internal_rpc_error, invalid_root_key_request_rpc_error, root_key_answer_rpc_error,
    },
};
use alloy_primitives::{Address, B256};
use jsonrpsee::{
    core::{RpcResult, async_trait},
    server::ServerBuilder,
};
use secp256k1::PublicKey;
use seismic_attestation::{
    NetworkId,
    bindings::{binding64_from_digest32, tx_io_binding},
    generate_evidence,
};
use seismic_attestation_rpc::{AttestationRpcServer, TxIoAttestationResponse};
use seismic_custodian_ipc::{CustodianClient, IpcError};
use std::{net::SocketAddr, path::PathBuf};
use tracing::{info, warn};

#[derive(Clone)]
pub struct AttestationService {
    /// Unix-socket path of the key custodian, the separate local process that
    /// owns `root_key`. This service holds no key material: each method opens
    /// a connection here for its key operations (a handful of requests per
    /// process lifetime, so no pooling).
    custodian_socket: PathBuf,
    /// This node's network identity: `H(network-manifest.json)`. Every
    /// attestation binding this server mints or verifies is scoped to it.
    network_id: NetworkId,
    /// Admission gate for joining peers: their verified measurements must be
    /// accepted by the on-chain `MeasurementRegistry`. See [`crate::admission`].
    admission: RegistryAdmission,
}

impl AttestationService {
    pub fn new(
        custodian_socket: PathBuf,
        network_id: NetworkId,
        admission: RegistryAdmission,
    ) -> Self {
        Self {
            custodian_socket,
            network_id,
            admission,
        }
    }

    async fn connect_custodian(&self) -> Result<CustodianClient, IpcError> {
        CustodianClient::connect(&self.custodian_socket).await
    }
}

#[async_trait]
impl NodeStatusRpcServer for AttestationService {
    /// Health check endpoint that returns "OK" if service is running
    async fn health_check(&self) -> RpcResult<String> {
        Ok("OK".to_string())
    }

    /// Serve the first-boot LUKS-wipe progress the setup-persistent-luks
    /// script publishes (read-only; `Idle` when no wipe is in flight). See
    /// [`crate::luks_status`].
    async fn get_luks_provisioning_status(&self) -> RpcResult<LuksProvisioningStatus> {
        Ok(crate::luks_status::read())
    }
}

#[async_trait]
impl AttestationRpcServer for AttestationService {
    /// Get the network root key for a booting peer, AEAD-wrapped.
    ///
    /// Verifies the requester's attestation, has the custodian wrap the root
    /// key to its attested ephemeral key, and returns the wrapped key plus our
    /// own quote over the response transcript. See [`crate::bootstrap`].
    async fn get_wrapped_root_key(&self, request: Vec<u8>) -> RpcResult<Vec<u8>> {
        let request: RootKeyRequest =
            serde_json::from_slice(&request).map_err(invalid_root_key_request_rpc_error)?;

        let mut custodian = self
            .connect_custodian()
            .await
            .map_err(|error| internal_rpc_error("connecting to custodian", error))?;
        let response = answer_root_key_request(
            &request,
            &self.network_id,
            &mut custodian,
            &self.admission,
            ATTESTATION_TYPE,
        )
        .await
        .map_err(root_key_answer_rpc_error)?;

        serde_json::to_vec(&response)
            .map_err(|error| internal_rpc_error("serializing root-key response", error))
    }

    /// Generate complete evidence bound to this service's tx-io public key,
    /// network identity, and the requested key epoch.
    async fn get_tx_io_attestation_evidence(
        &self,
        epoch: u64,
    ) -> RpcResult<TxIoAttestationResponse> {
        let mut custodian = self
            .connect_custodian()
            .await
            .map_err(|error| internal_rpc_error("connecting to custodian", error))?;
        // Public-only on purpose: minting evidence needs `tx_io_pk`, never the
        // secret half, and the production ACL grants this service nothing more.
        let tx_io_pk = custodian
            .get_tx_io_public_key(epoch)
            .await
            .map_err(|error| internal_rpc_error("fetching tx-io public key", error))?;
        let binding = tx_io_binding(&self.network_id, &tx_io_pk.pk, epoch);
        let evidence = generate_evidence(ATTESTATION_TYPE, binding64_from_digest32(binding))
            .map_err(|error| internal_rpc_error("generating tx-io evidence", error))?;

        Ok(TxIoAttestationResponse {
            tx_io_pk: PublicKey::from_slice(&tx_io_pk.pk)
                .map_err(|error| internal_rpc_error("decoding tx-io public key", error))?,
            epoch,
            evidence,
        })
    }
}

pub async fn start_server(addr: SocketAddr, args: Args) -> anyhow::Result<()> {
    // Derive this node's network identity from the manifest tdx-init dropped on
    // tmpfs. Fatal if absent/malformed: without it every attestation binding is
    // unscoped, so we refuse to serve rather than fall back to an unbound quote.
    let (manifest, network_id) = load_manifest(NETWORK_MANIFEST_PATH)?;
    info!("Derived network_id {network_id} from {NETWORK_MANIFEST_PATH}");

    // Joining peers are admitted by the live on-chain policy: the manifest
    // names the registry and the genesis that identifies the chain to read it
    // on, our own reth answers for both. Construction is lazy — no connection
    // until a join arrives — so serving never waits on reth; a join that beats
    // reth's startup is denied (fail closed) and the requester retries.
    let registry = Address::from(manifest.measurements.contracts.registry);
    let pinned_genesis = B256::from(manifest.eth.genesis_hash);
    let mut admission = RegistryAdmission::new(args.reth_rpc_url.clone(), registry, pinned_genesis);
    if let Some(max_policy_age) = args.max_policy_age {
        warn!(
            "Admission accepts a finalized policy view no older than {max_policy_age:?} (test override)"
        );
        admission = admission.with_max_policy_age(max_policy_age);
    }
    info!(
        "Gating joining peers via MeasurementRegistry at {registry} over {}, \
         on the chain with genesis {pinned_genesis}",
        args.reth_rpc_url
    );

    // The root key lives in the key custodian, a separate local process with
    // no network listener; every key operation goes through its Unix socket.
    // Serve only once the custodian holds the root key, so peers and reth
    // never observe a listener whose key operations cannot succeed yet.
    ensure_root_key_present(&args.custodian_socket, &args.peers, &network_id).await?;

    let server = ServerBuilder::default().build(addr).await?;

    let service = AttestationService::new(args.custodian_socket, network_id, admission);
    let mut rpc = NodeStatusRpcServer::into_rpc(service.clone());
    rpc.merge(AttestationRpcServer::into_rpc(service))?;
    let handle = server.start(rpc);

    info!("Attestation-service JSON-RPC server started at {}", addr);

    handle.stopped().await;

    Ok(())
}
