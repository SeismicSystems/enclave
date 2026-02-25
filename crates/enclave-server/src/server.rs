use crate::snapshot::{DATA_DISK_DIR, SNAPSHOT_FILE_PREFIX, restore_from_encrypted_snapshot};
use crate::{
    Args,
    attestation::AttestationAgent,
    key_manager::KeyManager,
    summit::run_summit_socket,
    utils::{anyhow_to_rpc_error, string_to_rpc_error},
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
use std::fs;
use std::path::Path;
use std::{net::SocketAddr, time::Duration};
use tokio::io::AsyncWriteExt as _;
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
    async fn download_encrypted_snapshot(&self, epoch: u64, url: String) -> RpcResult<()> {
        // Download the file
        let response = reqwest::get(&url)
            .await
            .map_err(|e| string_to_rpc_error(format!("Failed to download snapshot: {}", e)))?;

        if !response.status().is_success() {
            return Err(string_to_rpc_error(format!(
                "HTTP error: {}",
                response.status()
            )));
        }

        let bytes = response
            .bytes()
            .await
            .map_err(|e| string_to_rpc_error(format!("Failed to read response body: {}", e)))?;

        // Create the filename
        let filename = format!("{SNAPSHOT_FILE_PREFIX}-{epoch}.tar.lz4.enc");

        // Write to file
        let mut file = tokio::fs::File::create(format!("{DATA_DISK_DIR}/{filename}"))
            .await
            .map_err(|e| {
                string_to_rpc_error(format!("Failed to create file {}: {}", filename, e))
            })?;

        file.write_all(&bytes).await.map_err(|e| {
            string_to_rpc_error(format!("Failed to write to file {}: {}", filename, e))
        })?;

        Ok(())
    }

    /// Restores from an encrypted snapshot
    async fn restore_from_encrypted_snapshot(&self, epoch: u64) -> RpcResult<()> {
        restore_from_encrypted_snapshot(
            &self.key_manager,
            epoch,
            format!("{DATA_DISK_DIR}/{epoch}-snapshot.tar.lz4.enc"),
        )
        .await
        .map_err(|e| string_to_rpc_error(format!("Failed to restore from checkpoint: {e}")))
    }

    /// Get an encrypted snapshot from this servers database
    async fn get_encrypted_snapshot(&self, epoch: u64) -> RpcResult<Vec<u8>> {
        let snapshot_path = format!(
            "{}/{}-{}.tar.lz4.enc",
            DATA_DISK_DIR, SNAPSHOT_FILE_PREFIX, epoch
        );

        if !fs::exists(&snapshot_path).unwrap_or_default() {
            return Err(string_to_rpc_error(format!(
                "No snapshot for epoch {epoch} stored"
            )));
        }

        fs::read(snapshot_path).map_err(|e| {
            string_to_rpc_error(format!(
                "Failed to read snapshot for epoch {}: {}",
                epoch, e
            ))
        })
    }

    /// List all encrypted snapshots stored in this enclave
    async fn list_all_encrypted_snapshots(&self) -> RpcResult<Vec<u64>> {
        let dir_path = Path::new(DATA_DISK_DIR);

        let entries = fs::read_dir(dir_path).map_err(|e| {
            string_to_rpc_error(format!("Failed to read snapshots directory: {}", e))
        })?;

        let mut epochs = Vec::new();
        let prefix = format!("{}-", SNAPSHOT_FILE_PREFIX);
        let suffix = ".tar.lz4.enc";

        for entry in entries {
            let entry = entry.map_err(|e| {
                string_to_rpc_error(format!("Failed to read directory entry: {}", e))
            })?;

            if let Some(filename) = entry.file_name().to_str() {
                if filename.starts_with(&prefix) && filename.ends_with(suffix) {
                    // Extract epoch from filename
                    let epoch_str = filename
                        .strip_prefix(&prefix)
                        .and_then(|s| s.strip_suffix(suffix));

                    if let Some(epoch_str) = epoch_str {
                        if let Ok(epoch) = epoch_str.parse::<u64>() {
                            epochs.push(epoch);
                        }
                    }
                }
            }
        }

        epochs.sort_unstable();
        Ok(epochs)
    }

    /// List all encrypted snapshots stored in this enclave
    async fn list_latest_encrypted_snapshots(&self) -> RpcResult<u64> {
        let all_snapshots = self.list_all_encrypted_snapshots().await?;

        all_snapshots
            .into_iter()
            .max()
            .ok_or_else(|| string_to_rpc_error("No snapshots found".to_string()))
    }
}

pub async fn start_server(addr: SocketAddr, args: Args) -> anyhow::Result<()> {
    let attestation_agent = AttestationAgent::new().unwrap();

    let key_manager = if args.genesis_node {
        KeyManager::new_as_genesis()?
    } else {
        fetch_root_key_from_peers(args.peers, &attestation_agent).await
    };

    let summit_handle = tokio::spawn(run_summit_socket(args.summit_socket, key_manager.clone()));

    let server = ServerBuilder::default().build(addr).await?;

    let handle = server.start(TdxQuoteServer::new(attestation_agent, key_manager).into_rpc());

    info!("TDX Quote JSON-RPC Server started at {}", addr);

    handle.stopped().await;

    // server stopped abort the summit socket
    summit_handle.abort();

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
