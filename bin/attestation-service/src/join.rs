//! This node's own join: obtaining the network root key at boot.
//!
//! A node that already holds the key — the genesis node, or one whose custodian
//! kept it across a restart — has nothing to do here. A keyless one runs the
//! requester side of the bootstrap handshake ([`crate::bootstrap`]) against its
//! configured peers until one answers, and this module is the loop around that:
//! which peer to ask and how long to wait before asking again.
//!
//! The counterpart is [`crate::server`], where this same process answers that
//! handshake for the nodes joining after it.

use crate::{
    ATTESTATION_TYPE,
    admission::DangerouslyAdmitAnyAzureGuest,
    bootstrap::{RootKeyResponse, build_root_key_request, verify_root_key_response},
};
use anyhow::Context as _;
use jsonrpsee::http_client::HttpClientBuilder;
use secp256k1::PublicKey;
use seismic_attestation::NetworkId;
use seismic_attestation_rpc::AttestationRpcClient as _;
use seismic_custodian_ipc::{CreateRootKeyBootstrapAttemptResult, CustodianClient};
use std::{path::Path, time::Duration};
use tracing::{info, warn};

/// Poll interval while waiting for the custodian socket to come up.
const CUSTODIAN_RETRY_INTERVAL: Duration = Duration::from_secs(1);

/// Block until the local custodian holds the network root key.
///
/// The first `CreateRootKeyBootstrapAttempt` doubles as the readiness probe
/// and the state query (there is deliberately no separate state RPC): a
/// custodian that already holds the key — genesis, or a bootstrap completed
/// before this service restarted — answers `RootKeyAlreadyPresent` and we
/// proceed straight to serving. Only a keyless custodian sends us into the
/// peer-fetch loop; the probe's retained attempt is superseded by the fresh
/// attempt each fetch try creates.
pub(crate) async fn ensure_root_key_present(
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

    // The joiner's appraisal of the responder is intentionally permissive for
    // now; see [`DangerouslyAdmitAnyAzureGuest`].
    let request_binding = verify_root_key_response(
        &response,
        &request,
        network_id,
        &DangerouslyAdmitAnyAzureGuest,
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
