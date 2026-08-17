//! This node's own join: obtaining the network root key at boot.
//!
//! A node that already holds the key — the genesis node, or one whose custodian
//! kept it across a restart — has nothing to do here. A keyless one runs the
//! requester side of the bootstrap handshake ([`crate::bootstrap`]) against its
//! configured peers until one answers, and this module is the loop around that:
//! which peer to ask, what a refusal says about this node, and how long to wait
//! before asking again.
//!
//! The counterpart is [`crate::server`], where this same process answers that
//! handshake for the nodes joining after it.

use crate::{
    ATTESTATION_TYPE,
    admission::DangerouslyAdmitAnyAzureGuest,
    bootstrap::{RootKeyResponse, build_root_key_request, verify_root_key_response},
    rpc_error::RootKeyRefusal,
};
use anyhow::Context as _;
use jsonrpsee::{core::ClientError, http_client::HttpClientBuilder};
use secp256k1::PublicKey;
use seismic_attestation::NetworkId;
use seismic_attestation_rpc::AttestationRpcClient as _;
use seismic_custodian_ipc::{CreateRootKeyBootstrapAttemptResult, CustodianClient};
use std::{path::Path, time::Duration};
use tracing::{error, info, warn};

/// Poll interval while waiting for the custodian socket to come up.
const CUSTODIAN_RETRY_INTERVAL: Duration = Duration::from_secs(1);

/// How long the peer loop waits between passes over the peer list while some
/// peer may yet answer: one that is unreachable, restarting, or reading a chain
/// it cannot decide on today can answer minutes from now.
const PEER_CYCLE_INTERVAL: Duration = Duration::from_secs(30);

/// How long it waits between passes once every peer has reached the same
/// verdict on this node. Rotating peers buys nothing here — they all read the
/// same evidence and the same on-chain policy — so the loop stops polling at
/// join speed and just keeps the door open for the operator's fix.
const REFUSED_CYCLE_INTERVAL: Duration = Duration::from_secs(5 * 60);

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
///
/// Every refusal is read for what it says about this node (see
/// [`RootKeyRefusal`]), which sets what the operator is told and how long the
/// next pass waits. The loop never gives up either way: a policy update can accept
/// this node minutes later, and an operator repairing a peer makes that peer
/// answerable again.
async fn fetch_root_key_from_peers(
    custodian_socket: &Path,
    peers: &[String],
    network_id: &NetworkId,
) {
    info!("Starting root key fetching from peers");
    loop {
        let mut refusals = Vec::with_capacity(peers.len());
        for peer in peers {
            match try_fetch_root_key_from_peer(custodian_socket, peer, network_id).await {
                Ok(()) => {
                    info!("Key received from {peer} and installed in the custodian");
                    return;
                }
                Err(error) => {
                    // The refusal names itself and the error carries the
                    // responder's own words; what to do about it is decided
                    // once the cycle ends, where the whole peer list has
                    // answered.
                    let refusal = peer_refusal(&error);
                    warn!(
                        ?refusal,
                        "Peer({peer}) did not give us the key; trying next peer\n{error:?}\n"
                    );
                    refusals.push(refusal);
                }
            }
        }

        // Only a refusal that names *this node* is a conclusion about it. Peers
        // that all failed to decide agreed on nothing but their own trouble,
        // and peers that disagreed leave the question open either way.
        let remedy = match unanimous_refusal(&refusals) {
            Some(RootKeyRefusal::RequesterEvidenceUnusable) => Some(
                "this node's own attestation stack yields no admissible identity; \
                 inspect it before this node can join",
            ),
            Some(RootKeyRefusal::RequesterIdentityNotAccepted) => Some(
                "this node's admission ID is not in the network's accepted set; \
                 have it accepted in the MeasurementRegistry, or boot an image \
                 whose ID already is",
            ),
            Some(RootKeyRefusal::ResponderUnavailable) | None => None,
        };

        let interval = match remedy {
            Some(remedy) => {
                error!(
                    "Every peer refused this node for the same reason, so the problem is \
                     this node's and not the peers': {remedy}. Still asking every {}s, \
                     in case the accepted set changes.",
                    REFUSED_CYCLE_INTERVAL.as_secs()
                );
                REFUSED_CYCLE_INTERVAL
            }
            None => {
                warn!(
                    "Cycled through all provided peers and did not receive root_key. \
                     Sleeping for {}s and trying again",
                    PEER_CYCLE_INTERVAL.as_secs()
                );
                PEER_CYCLE_INTERVAL
            }
        };
        tokio::time::sleep(interval).await;
    }
}

/// The refusal a full pass over the peer list agreed on, if it agreed on one:
/// `Some` only when every peer refused, and refused for the same reason.
///
/// Unanimity is what lets the caller read a requester refusal as this node's
/// own standing. One peer that is unreachable, broken, or of a different mind
/// is a peer that may be the wrong one, and telling an operator its image is
/// rejected on that say-so sends it after a fault it does not have. Peers that
/// disagree leave the loop asking rather than picking a side.
fn unanimous_refusal(refusals: &[Option<RootKeyRefusal>]) -> Option<RootKeyRefusal> {
    let first = (*refusals.first()?)?;
    refusals
        .iter()
        .all(|refusal| *refusal == Some(first))
        .then_some(first)
}

/// The refusal a peer sent back, if that is what ended this attempt.
///
/// A peer's answer reaches us as a JSON-RPC error object carrying one of the
/// codes in [`crate::rpc_error`]. Everything else the attempt can fail on — an
/// unreachable peer, a response we cannot verify, our own custodian — is not
/// the peer refusing and says nothing about this node.
fn peer_refusal(error: &anyhow::Error) -> Option<RootKeyRefusal> {
    match error.downcast_ref::<ClientError>()? {
        ClientError::Call(refusal) => RootKeyRefusal::from_code(refusal.code()),
        _ => None,
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

#[cfg(test)]
mod tests {
    use super::*;
    use jsonrpsee::types::{ErrorCode, ErrorObjectOwned};

    const NOT_ACCEPTED: Option<RootKeyRefusal> = Some(RootKeyRefusal::RequesterIdentityNotAccepted);
    const NO_IDENTITY: Option<RootKeyRefusal> = Some(RootKeyRefusal::RequesterEvidenceUnusable);
    const UNAVAILABLE: Option<RootKeyRefusal> = Some(RootKeyRefusal::ResponderUnavailable);

    /// An answer that came back with `code`, shaped the way the client
    /// surfaces a peer's JSON-RPC error object.
    fn answered(code: i32) -> anyhow::Error {
        ClientError::Call(ErrorObjectOwned::owned(code, "refused", None::<()>)).into()
    }

    /// Peers all saying the same thing is the one case a cycle can conclude
    /// on, and the refusal travels intact so the operator is sent to the right
    /// place.
    #[test]
    fn a_unanimous_cycle_reports_what_the_peers_agreed_on() {
        assert_eq!(
            unanimous_refusal(&[NOT_ACCEPTED, NOT_ACCEPTED, NOT_ACCEPTED]),
            NOT_ACCEPTED
        );
        assert_eq!(unanimous_refusal(&[NO_IDENTITY]), NO_IDENTITY);
        // Agreement that no peer could decide is agreement about the peers,
        // and the loop reads it as no conclusion about this node.
        assert_eq!(unanimous_refusal(&[UNAVAILABLE, UNAVAILABLE]), UNAVAILABLE);
    }

    /// One peer that answered anything else is enough to withhold the
    /// conclusion: it may be the peer that is wrong, and a node told its image
    /// is rejected goes looking for a fault it does not have.
    #[test]
    fn one_dissenting_peer_withholds_the_conclusion() {
        assert_eq!(unanimous_refusal(&[NOT_ACCEPTED, UNAVAILABLE]), None);
        assert_eq!(unanimous_refusal(&[NOT_ACCEPTED, None]), None);
        assert_eq!(unanimous_refusal(&[None, NOT_ACCEPTED]), None);
        assert_eq!(unanimous_refusal(&[NOT_ACCEPTED, NO_IDENTITY]), None);
    }

    /// A cycle nobody answered agreed on nothing, and a cycle with nothing in
    /// it agreed on less.
    #[test]
    fn a_cycle_without_refusals_concludes_nothing() {
        assert_eq!(unanimous_refusal(&[None, None]), None);
        assert_eq!(unanimous_refusal(&[]), None);
    }

    /// Each wire code the responder can send arrives as the refusal it stands
    /// for.
    #[test]
    fn the_wire_codes_arrive_as_refusals() {
        for refusal in [NOT_ACCEPTED, NO_IDENTITY, UNAVAILABLE] {
            let code = refusal.expect("a refusal under test").code();
            assert_eq!(peer_refusal(&answered(code)), refusal);
        }
    }

    /// Only a peer that refused says anything about this node. A peer we never
    /// reached, one that failed on its own plumbing, and our own custodian all
    /// leave its standing unsaid — so a cycle of them can never conclude the
    /// node is rejected.
    #[test]
    fn only_a_refusal_carries_a_verdict() {
        assert_eq!(
            peer_refusal(&answered(ErrorCode::InternalError.code())),
            None
        );
        assert_eq!(
            peer_refusal(&answered(ErrorCode::InvalidParams.code())),
            None
        );
        assert_eq!(
            peer_refusal(&ClientError::RequestTimeout.into()),
            None,
            "an unanswered request is not a refusal"
        );
        assert_eq!(
            peer_refusal(&anyhow::anyhow!("connecting to custodian")),
            None
        );
    }
}
