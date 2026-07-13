use crate::{
    Args,
    bootstrap::{
        RootKeyRequest, RootKeyResponse, answer_root_key_request, build_root_key_request,
        unwrap_root_key_from_response,
    },
    luks_keys,
    network::{NETWORK_MANIFEST_PATH, load_network_id},
    utils::{
        internal_rpc_error, invalid_root_key_request_rpc_error, root_key_request_denied_rpc_error,
    },
};
use anyhow::Context as _;
use jsonrpsee::{
    core::{RpcResult, async_trait},
    http_client::HttpClientBuilder,
    server::ServerBuilder,
};
use seismic_attestation::{
    AttestationType, NetworkId, SeismicMeasurementPolicy,
    bindings::{binding64_from_digest32, tx_io_binding},
    generate_evidence,
};
use seismic_attestation_rpc::{
    AttestationRpcClient as _, AttestationRpcServer, TxIoAttestationResponse,
};
use seismic_custodian_ipc::CUSTODIAN_SOCKET_PATH;
use seismic_enclave::{GetPurposeKeysResponse, LuksProvisioningStatus, api::TdxQuoteRpcServer};
use seismic_key_custodian::Custodian;
use std::{net::SocketAddr, path::Path, sync::Arc, time::Duration};
use tracing::{info, warn};

/// Attestation type this build mints and verifies evidence for. Azure TDX +
/// vTPM is the only supported surface today.
const ATTESTATION_TYPE: AttestationType = AttestationType::AzureTdx;

#[derive(Clone)]
pub struct TdxQuoteServer {
    /// `Arc` because the one `Custodian` per process (it is deliberately not
    /// `Clone`) is shared with the IPC socket thread spawned in
    /// [`start_server`]; every method on it is `&self`, so no lock.
    /// TODO: once the custodian runs as its own process and this server reaches it
    /// over the socket, drop the `Arc` with the field.
    custodian: Arc<Custodian>,
    /// This node's network identity: `H(network-manifest.json)`. Every
    /// attestation binding this server mints or verifies is scoped to it.
    network_id: NetworkId,
}

impl TdxQuoteServer {
    pub fn new(custodian: Arc<Custodian>, network_id: NetworkId) -> Self {
        Self {
            custodian,
            network_id,
        }
    }
}

#[async_trait]
impl TdxQuoteRpcServer for TdxQuoteServer {
    /// Health check endpoint that returns "OK" if service is running
    async fn health_check(&self) -> RpcResult<String> {
        Ok("OK".to_string())
    }

    /// Serve reth's purpose-key startup fetch.
    ///
    /// TODO: move this operation to the custodian's local IPC API.
    async fn get_purpose_keys(&self, epoch: u64) -> RpcResult<GetPurposeKeysResponse> {
        Ok(GetPurposeKeysResponse {
            tx_io_sk: self.custodian.get_tx_io_sk(epoch),
            tx_io_pk: self.custodian.get_tx_io_pk(epoch),
            snapshot_key_bytes: self.custodian.get_snapshot_key(epoch).into(),
            rng_keypair: self.custodian.get_rng_keypair(epoch),
        })
    }

    /// Serve the first-boot LUKS-wipe progress the setup-persistent-luks
    /// script publishes (read-only; `Idle` when no wipe is in flight). See
    /// [`crate::luks_status`].
    async fn get_luks_provisioning_status(&self) -> RpcResult<LuksProvisioningStatus> {
        Ok(crate::luks_status::read())
    }
}

#[async_trait]
impl AttestationRpcServer for TdxQuoteServer {
    /// Get the network root key for a booting peer, AEAD-wrapped.
    ///
    /// Verifies the requester's attestation, ECDHs to its attested ephemeral
    /// key, and returns the root key sealed under the derived key plus our own
    /// quote over the response transcript. See [`crate::bootstrap`].
    async fn get_wrapped_root_key(&self, request: Vec<u8>) -> RpcResult<Vec<u8>> {
        let request: RootKeyRequest =
            serde_json::from_slice(&request).map_err(invalid_root_key_request_rpc_error)?;

        let response = answer_root_key_request(
            &request,
            &self.network_id,
            &self.custodian,
            bootstrap_measurement_policy(),
            ATTESTATION_TYPE,
        )
        .await
        .map_err(root_key_request_denied_rpc_error)?;

        serde_json::to_vec(&response)
            .map_err(|error| internal_rpc_error("serializing root-key response", error))
    }

    /// Generate complete evidence bound to this service's tx-io public key,
    /// network identity, and the requested key epoch.
    async fn get_tx_io_attestation_evidence(
        &self,
        epoch: u64,
    ) -> RpcResult<TxIoAttestationResponse> {
        let tx_io_pk = self.custodian.get_tx_io_pk(epoch);
        let binding = tx_io_binding(&self.network_id, &tx_io_pk.serialize(), epoch);
        let evidence = generate_evidence(ATTESTATION_TYPE, binding64_from_digest32(binding))
            .map_err(|error| internal_rpc_error("generating tx-io evidence", error))?;

        Ok(TxIoAttestationResponse {
            tx_io_pk,
            epoch,
            evidence,
        })
    }
}

pub async fn start_server(addr: SocketAddr, args: Args) -> anyhow::Result<()> {
    // Derive this node's network identity from the manifest tdx-init dropped on
    // tmpfs. Fatal if absent/malformed: without it every attestation binding is
    // unscoped, so we refuse to serve rather than fall back to an unbound quote.
    let network_id = load_network_id(NETWORK_MANIFEST_PATH)?;
    info!("Derived network_id {network_id} from {NETWORK_MANIFEST_PATH}");

    let custodian = if args.genesis_node {
        info!("Starting as genesis node; generating fresh network root key");
        Custodian::new_as_genesis()?
    } else {
        if args.peers.is_empty() {
            anyhow::bail!(
                "Non-genesis enclave started with no peers. Either:\n  \
                 - set SEISMIC_ENCLAVE_PEERS to a comma-separated list of \
                 peer enclave URLs (e.g. http://10.0.0.1:7878) to fetch \
                 the root_key from an existing peer, OR\n  \
                 - set SEISMIC_ENCLAVE_GENESIS_NODE=true to bootstrap a new \
                 chain (set this on exactly one node in the deployment; \
                 setting it on multiple nodes causes a silent network split)."
            );
        }
        info!(
            "Starting as peer node; fetching root key from {} peer(s)",
            args.peers.len()
        );
        fetch_root_key_from_peers(args.peers, &network_id).await
    };

    // Hand off the LUKS storage + header-MAC keys to setup-persistent-luks
    // (seismic-images script) via a tmpfs file. Fatal on failure — without
    // these keys reaching the LUKS-setup script, /persistent can't
    // mount and the node can't proceed past this boot.
    luks_keys::write_keys_for_luks_setup(&custodian)?;

    // The same process also serves local key ops over a Unix socket — the
    // seam along which the custodian later splits into its own process. The
    // transport is `seismic_custodian_ipc::server` (synchronous, hence the
    // dedicated thread); only dispatch (`crate::ipc`) lives here. No
    // production caller connects yet: in-process users call `Custodian`
    // directly and reth still fetches keys over HTTP `getPurposeKeys`, so
    // until the split moves them onto the socket, only the debug CLI (and
    // tests) exercise it. Bind failure is fatal anyway: a
    // node that can't serve the socket should fail this boot, not at the
    // split, and /run/seismic already had to exist for the manifest read.
    let custodian = Arc::new(custodian);
    let ipc_listener = seismic_custodian_ipc::server::bind(Path::new(CUSTODIAN_SOCKET_PATH))
        .with_context(|| format!("binding custodian socket {CUSTODIAN_SOCKET_PATH}"))?;
    let ipc_custodian = custodian.clone();
    std::thread::spawn(move || {
        seismic_custodian_ipc::server::serve(
            ipc_listener,
            seismic_custodian_ipc::server::MethodAcl::own_uid_only(),
            move |request| crate::ipc::dispatch(&ipc_custodian, request),
        )
    });

    let server = ServerBuilder::default().build(addr).await?;

    let quote_server = TdxQuoteServer::new(custodian, network_id);
    let mut rpc = TdxQuoteRpcServer::into_rpc(quote_server.clone());
    rpc.merge(AttestationRpcServer::into_rpc(quote_server))?;
    let handle = server.start(rpc);

    info!("TDX Quote JSON-RPC Server started at {}", addr);

    handle.stopped().await;

    Ok(())
}

/// Run the requester side of the v2 bootstrap against each peer until one
/// returns a root key we can verify and unwrap.
///
/// Per attempt: build a fresh attested request (new ephemeral key + nonce),
/// POST it, then verify the peer's response quote and AEAD-open the wrapped
/// key. A fresh ephemeral key per attempt means a failed exchange leaks nothing
/// reusable.
pub async fn fetch_root_key_from_peers(peers: Vec<String>, network_id: &NetworkId) -> Custodian {
    info!("Starting root key fetching from peers");
    loop {
        for peer in &peers {
            match try_fetch_root_key_from_peer(peer, network_id).await {
                Ok(root_key) => {
                    info!("Key received from {peer}. Starting key custodian");
                    return Custodian::new(root_key);
                }
                Err(e) => {
                    warn!(
                        "Peer({peer}) did not give us the key. Trying next peer... Reason: \n{e:?}\n"
                    );
                    continue;
                }
            }
        }

        warn!(
            "Cycled through all provided peers and did not receive root_key. Sleeping for 30 seconds and trying again"
        );
        tokio::time::sleep(Duration::from_secs(30)).await;
    }
}

/// One requester-side handshake against a single peer.
async fn try_fetch_root_key_from_peer(
    peer: &str,
    network_id: &NetworkId,
) -> anyhow::Result<[u8; 32]> {
    let (request, eph_sk_b) = build_root_key_request(network_id, ATTESTATION_TYPE)?;

    let client = HttpClientBuilder::default().build(peer)?;
    let request_bytes = serde_json::to_vec(&request)?;
    let response_bytes = client.get_wrapped_root_key(request_bytes).await?;
    let response: RootKeyResponse = serde_json::from_slice(&response_bytes)?;

    unwrap_root_key_from_response(
        &response,
        &request,
        &eph_sk_b,
        network_id,
        bootstrap_measurement_policy(),
    )
    .await
}

/// Measurement policy for verifying the *other* side of the bootstrap handshake.
///
/// TODO(bootstrap): load the policy pinned by the manifest's
/// `measurements.bootstrap_policy_hash` (the seismic-images
/// `build/measurements.json` artifact) once it is delivered to the node, and
/// check the artifact bytes against that hash. Until that artifact is wired in,
/// this accepts any measurements after the backend's cryptographic quote
/// verification succeeds — adequate for bringing the encrypted transcript up,
/// NOT a production allowlist.
fn bootstrap_measurement_policy() -> SeismicMeasurementPolicy {
    warn!(
        "bootstrap: using dangerously-permissive measurement policy; \
         peer image measurements are NOT being checked against an allowlist"
    );
    SeismicMeasurementPolicy::dangerously_accept_any_for_testing(ATTESTATION_TYPE)
}
