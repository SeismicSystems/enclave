use crate::{
    Args,
    bootstrap::{
        RootKeyRequest, RootKeyResponse, answer_root_key_request, build_root_key_request,
        verify_root_key_response,
    },
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
use secp256k1::PublicKey;
use seismic_attestation::{
    AttestationType, NetworkId, SeismicMeasurementPolicy,
    bindings::{binding64_from_digest32, tx_io_binding},
    generate_evidence,
};
use seismic_attestation_rpc::{
    AttestationRpcClient as _, AttestationRpcServer, TxIoAttestationResponse,
};
use seismic_custodian_ipc::{
    CreateRootKeyBootstrapAttemptResult, CustodianClient, IpcError, RngKeypairBytes,
    SnapshotKeyBytes, TxIoKeypairBytes,
};
use seismic_enclave::{
    GetPurposeKeysResponse, LuksProvisioningStatus, SchnorrkelKeypair,
    api::{NodeStatusRpcServer, PurposeKeysRpcServer},
};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};
use tracing::{info, warn};

/// Attestation type this build mints and verifies evidence for. Azure TDX +
/// vTPM is the only supported surface today.
const ATTESTATION_TYPE: AttestationType = AttestationType::AzureTdx;

/// Poll interval while waiting for the custodian socket to come up.
const CUSTODIAN_RETRY_INTERVAL: Duration = Duration::from_secs(1);

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
}

impl AttestationService {
    pub fn new(custodian_socket: PathBuf, network_id: NetworkId) -> Self {
        Self {
            custodian_socket,
            network_id,
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
impl PurposeKeysRpcServer for AttestationService {
    /// Serve reth's purpose-key startup fetch from the custodian socket.
    async fn get_purpose_keys(&self, epoch: u64) -> RpcResult<GetPurposeKeysResponse> {
        let mut custodian = self
            .connect_custodian()
            .await
            .map_err(|error| internal_rpc_error("connecting to custodian", error))?;
        let tx_io = custodian
            .get_tx_io_keypair(epoch)
            .await
            .map_err(|error| internal_rpc_error("fetching tx-io keypair", error))?;
        let rng = custodian
            .get_rng_keypair(epoch)
            .await
            .map_err(|error| internal_rpc_error("fetching rng keypair", error))?;
        let snapshot = custodian
            .get_snapshot_key(epoch)
            .await
            .map_err(|error| internal_rpc_error("fetching snapshot key", error))?;

        purpose_keys_response(&tx_io, &rng, &snapshot)
            .map_err(|error| internal_rpc_error("decoding custodian key bytes", error))
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

/// Convert the custodian's raw key bytes into the typed purpose-key DTO.
fn purpose_keys_response(
    tx_io: &TxIoKeypairBytes,
    rng: &RngKeypairBytes,
    snapshot: &SnapshotKeyBytes,
) -> anyhow::Result<GetPurposeKeysResponse> {
    Ok(GetPurposeKeysResponse {
        tx_io_sk: secp256k1::SecretKey::from_byte_array(&tx_io.sk)
            .context("tx-io secret bytes are not a valid secp256k1 scalar")?,
        tx_io_pk: PublicKey::from_slice(&tx_io.pk)
            .context("tx-io public bytes are not a valid secp256k1 point")?,
        snapshot_key_bytes: snapshot.key,
        rng_keypair: SchnorrkelKeypair::from_bytes(&rng.keypair)
            .map_err(|error| anyhow::anyhow!("rng bytes are not a schnorrkel keypair: {error}"))?,
    })
}

pub async fn start_server(addr: SocketAddr, args: Args) -> anyhow::Result<()> {
    // Derive this node's network identity from the manifest tdx-init dropped on
    // tmpfs. Fatal if absent/malformed: without it every attestation binding is
    // unscoped, so we refuse to serve rather than fall back to an unbound quote.
    let network_id = load_network_id(NETWORK_MANIFEST_PATH)?;
    info!("Derived network_id {network_id} from {NETWORK_MANIFEST_PATH}");

    // The root key lives in the key custodian, a separate local process with
    // no network listener; every key operation goes through its Unix socket.
    // Serve only once the custodian holds the root key, so peers and reth
    // never observe a listener whose key operations cannot succeed yet.
    ensure_root_key_present(&args.custodian_socket, &args.peers, &network_id).await?;

    let server = ServerBuilder::default().build(addr).await?;

    let service = AttestationService::new(args.custodian_socket, network_id);
    let mut rpc = NodeStatusRpcServer::into_rpc(service.clone());
    rpc.merge(PurposeKeysRpcServer::into_rpc(service.clone()))?;
    rpc.merge(AttestationRpcServer::into_rpc(service))?;
    let handle = server.start(rpc);

    info!("Attestation-service JSON-RPC server started at {}", addr);

    handle.stopped().await;

    Ok(())
}

/// Block until the local custodian holds the network root key.
///
/// The first `CreateRootKeyBootstrapAttempt` doubles as the readiness probe
/// and the state query (there is deliberately no separate state RPC): a
/// custodian that already holds the key — genesis, or a bootstrap completed
/// before this service restarted — answers `RootKeyAlreadyPresent` and we
/// proceed straight to serving. Only a keyless custodian sends us into the
/// peer-fetch loop; the probe's retained attempt is superseded by the fresh
/// attempt each fetch try creates.
async fn ensure_root_key_present(
    custodian_socket: &Path,
    peers: &[String],
    network_id: &NetworkId,
) -> anyhow::Result<()> {
    let mut custodian = connect_custodian_when_ready(custodian_socket).await;
    if matches!(
        custodian.create_root_key_bootstrap_attempt().await?,
        CreateRootKeyBootstrapAttemptResult::RootKeyAlreadyPresent
    ) {
        info!("Custodian already holds the root key");
        return Ok(());
    }

    if peers.is_empty() {
        anyhow::bail!(
            "The custodian holds no root key and no peers are configured. Either:\n  \
             - set SEISMIC_ROOT_KEY_PEERS to a comma-separated list of \
             peer enclave URLs (e.g. http://10.0.0.1:7878) to fetch \
             the root_key from an existing peer, OR\n  \
             - run seismic-custodian-service with --genesis-node to bootstrap a new \
             chain (set this on exactly one node in the deployment; \
             setting it on multiple nodes causes a silent network split)."
        );
    }

    fetch_root_key_from_peers(custodian_socket, peers, network_id).await;
    Ok(())
}

/// Connect to the custodian socket, waiting for it to appear. systemd starts
/// the custodian first, but ordering covers process start, not the bind;
/// retry across the gap instead of failing the boot.
async fn connect_custodian_when_ready(custodian_socket: &Path) -> CustodianClient {
    loop {
        match CustodianClient::connect(custodian_socket).await {
            Ok(client) => return client,
            Err(error) => {
                warn!(
                    "Custodian socket {} not ready ({error}); retrying",
                    custodian_socket.display()
                );
                tokio::time::sleep(CUSTODIAN_RETRY_INTERVAL).await;
            }
        }
    }
}

/// Run the requester side of the v2 bootstrap against each peer until one
/// exchange installs the root key in the local custodian.
///
/// Per attempt: have the custodian retain a fresh ephemeral key, build an
/// attested request around its public half and a fresh nonce, POST it, verify
/// the peer's response quote, and hand the still-wrapped key back to the
/// custodian to open and install. A fresh attempt per try means a failed
/// exchange leaks nothing reusable.
async fn fetch_root_key_from_peers(
    custodian_socket: &Path,
    peers: &[String],
    network_id: &NetworkId,
) {
    info!("Starting root key fetching from peers");
    loop {
        for peer in peers {
            match try_fetch_root_key_from_peer(custodian_socket, peer, network_id).await {
                Ok(()) => {
                    info!("Key received from {peer} and installed in the custodian");
                    return;
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
///
/// The custodian retains the attempt's ephemeral secret; this process sees
/// only the public half, runs the evidence exchange, and passes the
/// still-wrapped root key back for install.
async fn try_fetch_root_key_from_peer(
    custodian_socket: &Path,
    peer: &str,
    network_id: &NetworkId,
) -> anyhow::Result<()> {
    // Fresh connection per attempt so a custodian restart mid-loop costs only
    // this attempt. A restart also drops its retained attempt, in which case
    // the install below fails and the next try starts a clean exchange.
    let mut custodian = CustodianClient::connect(custodian_socket)
        .await
        .context("connecting to custodian")?;
    let attempt = match custodian.create_root_key_bootstrap_attempt().await? {
        CreateRootKeyBootstrapAttemptResult::Created(attempt) => attempt,
        CreateRootKeyBootstrapAttemptResult::RootKeyAlreadyPresent => return Ok(()),
    };
    let requester_eph_pk = PublicKey::from_slice(&attempt.requester_eph_pk)
        .context("custodian returned an invalid requester ephemeral key")?;
    let request = build_root_key_request(network_id, &requester_eph_pk, ATTESTATION_TYPE)?;

    let client = HttpClientBuilder::default().build(peer)?;
    let request_bytes = serde_json::to_vec(&request)?;
    let response_bytes = client.get_wrapped_root_key(request_bytes).await?;
    let response: RootKeyResponse = serde_json::from_slice(&response_bytes)?;

    let request_binding = verify_root_key_response(
        &response,
        &request,
        network_id,
        bootstrap_measurement_policy(),
    )
    .await?;

    // Both install outcomes leave the custodian holding the root key.
    custodian
        .install_root_key_from_verified_bootstrap_response(
            attempt.attempt_id,
            request_binding,
            response.eph_pk_a.serialize(),
            response.wrapped,
        )
        .await
        .context("installing root key in the custodian")?;
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use seismic_custodian::Custodian;

    const ROOT_KEY: [u8; 32] = [7u8; 32];

    // Parity with the pre-split in-process handler: the custodian's socket
    // bytes decode to exactly the keys it derives.
    #[test]
    fn purpose_keys_response_matches_custodian_derivation() {
        let custodian = Custodian::new(ROOT_KEY);
        let response = purpose_keys_response(
            &TxIoKeypairBytes {
                sk: custodian.get_tx_io_sk(0).secret_bytes(),
                pk: custodian.get_tx_io_pk(0).serialize(),
            },
            &RngKeypairBytes {
                keypair: custodian.get_rng_keypair(0).to_bytes().to_vec(),
            },
            &SnapshotKeyBytes {
                key: custodian.get_snapshot_key(0).into(),
            },
        )
        .expect("decode purpose keys");

        assert_eq!(response.tx_io_sk, custodian.get_tx_io_sk(0));
        assert_eq!(response.tx_io_pk, custodian.get_tx_io_pk(0));
        assert_eq!(
            response.rng_keypair.secret,
            custodian.get_rng_keypair(0).secret
        );
        let expected_snapshot: [u8; 32] = custodian.get_snapshot_key(0).into();
        assert_eq!(response.snapshot_key_bytes, expected_snapshot);
    }

    #[test]
    fn purpose_keys_response_rejects_invalid_bytes() {
        let custodian = Custodian::new(ROOT_KEY);
        let tx_io = TxIoKeypairBytes {
            sk: custodian.get_tx_io_sk(0).secret_bytes(),
            pk: custodian.get_tx_io_pk(0).serialize(),
        };
        let rng = RngKeypairBytes {
            keypair: custodian.get_rng_keypair(0).to_bytes().to_vec(),
        };
        let snapshot = SnapshotKeyBytes { key: [3; 32] };

        // Zero is not a secp256k1 scalar; an all-zero prefix byte is not a
        // valid compressed point; 4 bytes are not a schnorrkel keypair.
        let bad_sk = TxIoKeypairBytes {
            sk: [0; 32],
            pk: tx_io.pk,
        };
        assert!(purpose_keys_response(&bad_sk, &rng, &snapshot).is_err());

        let bad_pk = TxIoKeypairBytes {
            sk: tx_io.sk,
            pk: [0; 33],
        };
        assert!(purpose_keys_response(&bad_pk, &rng, &snapshot).is_err());

        let bad_rng = RngKeypairBytes {
            keypair: vec![0; 4],
        };
        assert!(purpose_keys_response(&tx_io, &bad_rng, &snapshot).is_err());
    }
}
