use crate::{
    api::{TdxQuoteRpcClient, TdxQuoteRpcServer},
    attestation::AttestationAgent,
    key_manager::KeyManager,
    req_res::{AttestationGetEvidenceResponse, GetPurposeKeysResponse, ShareRootKeyResponse},
    utils::anyhow_to_rpc_error,
};
use dcap_rs::types::quotes::version_4::QuoteV4;
use jsonrpsee::{
    core::{RpcResult, async_trait},
    http_client::HttpClientBuilder,
    server::ServerBuilder,
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

    /// Prepares an encrypted snapshot
    async fn prepare_encrypted_snapshot(&self) -> RpcResult<()> {
        todo!()
    }

    /// Restores from an encrypted snapshot
    async fn restore_from_encrypted_snapshot(&self) -> RpcResult<()> {
        todo!()
    }
}

pub async fn start_server(
    addr: SocketAddr,
    genesis_node: bool,
    peers: Vec<String>,
) -> anyhow::Result<()> {
    let attestation_agent = AttestationAgent::new().unwrap();

    let key_manager = if genesis_node {
        KeyManager::new_as_genesis()?
    } else {
        fetch_root_key_from_peers(peers, &attestation_agent).await
    };

    let server = ServerBuilder::default().build(addr).await?;

    let handle = server.start(TdxQuoteServer::new(attestation_agent, key_manager).into_rpc());

    println!("TDX Quote JSON-RPC Server started at {}", addr);

    handle.stopped().await;
    Ok(())
}

pub async fn fetch_root_key_from_peers(
    peers: Vec<String>,
    attestation_agent: &AttestationAgent,
) -> KeyManager {
    // let peers: Vec<SocketAddr> = peers.iter().filter_map(|p| p.parse().ok()).collect();

    if peers.is_empty() {
        panic!("Started in non-genesis with no valid peers");
    }

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

            let Ok(res) = client.boot_share_root_key(evidence.quote.clone()).await else {
                warn!("Peer({peer}) did not give us the key: \n Trying next peer...");
                continue;
            };

            // We got the key
            info!("Key received. Starting Key manager");

            return KeyManager::new(res.root_key);
        }

        tracing::warn!(
            "Cycled through all provided peers and did not receive root_key. Sleeping for 30 seconds and trying again"
        );
        tokio::time::sleep(Duration::from_secs(30)).await;
    }
}
