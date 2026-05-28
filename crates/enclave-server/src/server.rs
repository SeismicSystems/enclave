use crate::{
    Args, attestation::AttestationAgent, key_manager::KeyManager, utils::anyhow_to_rpc_error,
};
use dcap_rs::types::quotes::version_4::QuoteV4;
use jsonrpsee::{
    core::{RpcResult, async_trait},
    http_client::HttpClientBuilder,
    server::ServerBuilder,
};
use seismic_enclave::{
    AttestationGetEvidenceResponse, GetPurposeKeysResponse, ShareRootKeyResponse,
    TdxQuoteRpcClient as _, api::TdxQuoteRpcServer,
};
use std::{net::SocketAddr, time::Duration};
use tracing::{info, warn};

pub struct TdxQuoteServer {
    attestation_agent: AttestationAgent,
    key_manager: KeyManager,
}

impl TdxQuoteServer {
    pub fn new(attestation_agent: AttestationAgent, key_manager: KeyManager) -> Self {
        Self {
            attestation_agent,
            key_manager,
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

    /// Generates attestation evidence from the attestation authority
    async fn get_attestation_evidence(&self) -> RpcResult<AttestationGetEvidenceResponse> {
        self.attestation_agent
            .get_attestation_evidence()
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

    /// Shares the root key with an existing node
    async fn boot_share_root_key(&self, quote: Vec<u8>) -> RpcResult<ShareRootKeyResponse> {
        let quote = QuoteV4::from_bytes(&quote); // todo(dalton): This will panic if invalid quote bytes are sent find a way to catch or alternative

        self.attestation_agent
            .verify_attestation_report(quote)
            .await
            .map_err(anyhow_to_rpc_error)?;

        // quote is good send key
        // Todo figure out encryption. We either force https or we handle encryption here
        let root_key = self.key_manager.get_root_key();
        Ok(ShareRootKeyResponse { root_key })
    }
}

pub async fn start_server(addr: SocketAddr, args: Args) -> anyhow::Result<()> {
    let attestation_agent = AttestationAgent::new().unwrap();

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
        fetch_root_key_from_peers(args.peers, &attestation_agent).await
    };

    let server = ServerBuilder::default().build(addr).await?;

    let handle = server.start(TdxQuoteServer::new(attestation_agent, key_manager).into_rpc());

    info!("TDX Quote JSON-RPC Server started at {}", addr);

    handle.stopped().await;

    Ok(())
}

pub async fn fetch_root_key_from_peers(
    peers: Vec<String>,
    attestation_agent: &AttestationAgent,
) -> KeyManager {
    info!("Starting root key fetching from peers");
    loop {
        let evidence = attestation_agent
            .get_attestation_evidence()
            .expect("Unable to get our own quote data");

        for peer in &peers {
            let Ok(client) = HttpClientBuilder::default().build(peer) else {
                warn!("Unable to make a connection with peer: {peer}. Trying next peer...");
                continue;
            };

            match client.boot_share_root_key(evidence.quote.clone()).await {
                Ok(res) => {
                    // We got the key
                    info!("Key received. Starting Key manager");
                    return KeyManager::new(res.root_key);
                }
                Err(e) => {
                    warn!(
                        "Peer({peer}) did not give us the key. Trying next peer... Reason: \n{e:?}\n"
                    );
                    continue;
                }
            }
        }

        tracing::warn!(
            "Cycled through all provided peers and did not receive root_key. Sleeping for 30 seconds and trying again"
        );
        tokio::time::sleep(Duration::from_secs(30)).await;
    }
}
