use crate::{
    Args,
    attestation::AttestationAgent,
    bootstrap::{
        RootKeyRequest, RootKeyResponse, answer_root_key_request, build_root_key_request,
        unwrap_root_key_from_response,
    },
    key_manager::KeyManager,
    luks_keys,
    network::{NETWORK_MANIFEST_PATH, load_network_id},
    utils::anyhow_to_rpc_error,
};
use dcap_rs::types::quotes::version_4::QuoteV4;
use jsonrpsee::{
    core::{RpcResult, async_trait},
    http_client::HttpClientBuilder,
    server::ServerBuilder,
};
use seismic_attestation::{AttestationType, NetworkId, SeismicMeasurementPolicy};
use seismic_enclave::{
    AttestationGetEvidenceResponse, GetPurposeKeysResponse, TdxQuoteRpcClient as _,
    api::TdxQuoteRpcServer,
};
use std::{net::SocketAddr, time::Duration};
use tracing::{info, warn};

/// Attestation type this build mints and verifies evidence for. Azure TDX +
/// vTPM is the only supported surface today (see `attestation::AttestationAgent`).
const ATTESTATION_TYPE: AttestationType = AttestationType::AzureTdx;

/// Epoch used for the standalone `getAttestationEvidence` tx_io binding.
const TX_IO_BINDING_EPOCH: u64 = 0;

pub struct TdxQuoteServer {
    attestation_agent: AttestationAgent,
    key_manager: KeyManager,
    /// This node's network identity: `H(network-manifest.json)`. Every
    /// attestation binding this server mints or verifies is scoped to it.
    network_id: NetworkId,
}

impl TdxQuoteServer {
    pub fn new(
        attestation_agent: AttestationAgent,
        key_manager: KeyManager,
        network_id: NetworkId,
    ) -> Self {
        Self {
            attestation_agent,
            key_manager,
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

    /// Get the secp256k1 public key
    async fn get_purpose_keys(&self, epoch: u64) -> RpcResult<GetPurposeKeysResponse> {
        Ok(GetPurposeKeysResponse {
            tx_io_sk: self.key_manager.get_tx_io_sk(epoch),
            tx_io_pk: self.key_manager.get_tx_io_pk(epoch),
            snapshot_key_bytes: self.key_manager.get_snapshot_key(epoch).into(),
            rng_keypair: self.key_manager.get_rng_keypair(epoch),
        })
    }

    /// Generates attestation evidence bound to this node's tx_io public key.
    ///
    /// The quote commits to `tx_io_binding(network_id, tx_io_pk, epoch)`, so a
    /// verifier learns the attested node holds this tx_io key on this network.
    async fn get_attestation_evidence(&self) -> RpcResult<AttestationGetEvidenceResponse> {
        let tx_io_pk = self
            .key_manager
            .get_tx_io_pk(TX_IO_BINDING_EPOCH)
            .serialize();
        let binding = seismic_attestation::bindings::tx_io_binding(
            &self.network_id,
            &tx_io_pk,
            TX_IO_BINDING_EPOCH,
        );
        self.attestation_agent
            .get_attestation_evidence(binding)
            .map_err(anyhow_to_rpc_error)
    }

    /// Evaluates provided attestation evidence
    async fn eval_attestation_evidence(
        &self,
        _hcl_report: Vec<u8>,
        quote: Vec<u8>,
    ) -> RpcResult<()> {
        let quote = QuoteV4::from_bytes(&quote); // todo(dalton): This will panic if invalid quote bytes are sent find a way to catch or alternative
        self.attestation_agent
            .verify_attestation_report(quote)
            .await
            .map_err(anyhow_to_rpc_error)
    }

    /// Get the network root key for a booting peer, AEAD-wrapped.
    ///
    /// Verifies the requester's attestation, ECDHs to its attested ephemeral
    /// key, and returns the root key sealed under the derived key plus our own
    /// quote over the response transcript. See [`crate::bootstrap`].
    async fn get_wrapped_root_key(&self, request: Vec<u8>) -> RpcResult<Vec<u8>> {
        let request: RootKeyRequest =
            serde_json::from_slice(&request).map_err(|e| anyhow_to_rpc_error(e.into()))?;

        let response = answer_root_key_request(
            &request,
            &self.network_id,
            &self.key_manager.get_root_key(),
            bootstrap_measurement_policy(),
            ATTESTATION_TYPE,
        )
        .await
        .map_err(anyhow_to_rpc_error)?;

        serde_json::to_vec(&response).map_err(|e| anyhow_to_rpc_error(e.into()))
    }
}

pub async fn start_server(addr: SocketAddr, args: Args) -> anyhow::Result<()> {
    let attestation_agent = AttestationAgent::new().unwrap();

    // Derive this node's network identity from the manifest tdx-init dropped on
    // tmpfs. Fatal if absent/malformed: without it every attestation binding is
    // unscoped, so we refuse to serve rather than fall back to an unbound quote.
    let network_id = load_network_id(NETWORK_MANIFEST_PATH)?;
    info!("Derived network_id {network_id} from {NETWORK_MANIFEST_PATH}");

    let key_manager = if args.genesis_node {
        info!("Starting as genesis node; generating fresh network root key");
        KeyManager::new_as_genesis()?
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
    luks_keys::write_keys_for_luks_setup(&key_manager)?;

    let server = ServerBuilder::default().build(addr).await?;

    let handle =
        server.start(TdxQuoteServer::new(attestation_agent, key_manager, network_id).into_rpc());

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
pub async fn fetch_root_key_from_peers(peers: Vec<String>, network_id: &NetworkId) -> KeyManager {
    info!("Starting root key fetching from peers");
    loop {
        for peer in &peers {
            match try_fetch_root_key_from_peer(peer, network_id).await {
                Ok(root_key) => {
                    info!("Key received from {peer}. Starting Key manager");
                    return KeyManager::new(root_key);
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
