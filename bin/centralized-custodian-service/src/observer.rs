//! Observer-mode client: fetching the root key and delivered envelopes from
//! the parent custodian.
//!
//! An observer custodian holds a copy of its parent's summit `node_key.pem`
//! (exactly as a summit observer node does) and authenticates by signing
//! fetches with a child key derived from it — the parent verifies against
//! the child pubkey it derives from its own key. Every exchange is
//! challenge-response over the parent's council port: request a single-use
//! nonce, sign `domain || nonce || request`, fetch.
//!
//! Trust boundary: envelopes from the parent are NEVER trusted as-is — each
//! one goes through [`CentralizedCustodianState::deliver`], which re-verifies
//! the council signature against this observer's own configured council
//! address and persists it durably before installing. The root key has no
//! council signature to check, so for it the parent is authenticated only by
//! address plus the fronting TLS/tunnel — and a locally persisted root key
//! is always cross-checked against the parent's (mismatch is boot-fatal).

use crate::root_key_file;
use crate::state::CentralizedCustodianState;
use anyhow::{Context as _, Result, anyhow, bail};
use seismic_council_delivery::{
    CouncilRequest, CouncilResponse, ObserverFetchRequest, ObserverQuery,
    observer_fetch_signing_payload,
};
use seismic_custodian_ipc::{read_frame_blocking, write_frame_blocking};
use seismic_network_manifest::NetworkId;
use seismic_observer_key::ObserverSigner;
use std::net::{TcpStream, ToSocketAddrs as _};
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;
use tracing::{info, warn};
use zeroize::Zeroizing;

/// Bounded so a hung parent can never hang this custodian's Unix-socket
/// clients: an on-demand fetch fails within these and the caller gets the
/// typed `EpochKeyUnavailable`.
pub const PARENT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub const PARENT_IO_TIMEOUT: Duration = Duration::from_secs(10);

pub struct ParentFetcher {
    parent_addr: String,
    signer: ObserverSigner,
    observer_index: u32,
    network_id: NetworkId,
    /// Serializes concurrent on-demand fetches so racing dispatch threads
    /// don't hammer the parent for the same gap.
    fetch_lock: Mutex<()>,
}

impl ParentFetcher {
    pub fn new(
        master_seed: &[u8; 32],
        namespace: &[u8; 32],
        observer_index: u32,
        parent_addr: String,
        network_id: NetworkId,
    ) -> Self {
        let signer = ObserverSigner::derive(master_seed, namespace, observer_index);
        info!(
            index = observer_index,
            child_public = hex::encode(signer.public_key()),
            parent = parent_addr,
            "observer mode: fetching from the parent custodian"
        );
        Self {
            parent_addr,
            signer,
            observer_index,
            network_id,
            fetch_lock: Mutex::new(()),
        }
    }

    fn connect(&self) -> Result<TcpStream> {
        let addr = self
            .parent_addr
            .to_socket_addrs()
            .with_context(|| format!("resolving parent custodian {}", self.parent_addr))?
            .next()
            .ok_or_else(|| anyhow!("parent custodian {} resolves to nothing", self.parent_addr))?;
        let stream = TcpStream::connect_timeout(&addr, PARENT_CONNECT_TIMEOUT)
            .with_context(|| format!("connecting to parent custodian {addr}"))?;
        stream.set_read_timeout(Some(PARENT_IO_TIMEOUT))?;
        stream.set_write_timeout(Some(PARENT_IO_TIMEOUT))?;
        Ok(stream)
    }

    /// One challenge → sign → fetch exchange on an open connection. Each
    /// nonce is single-use, so paging loops call this once per batch.
    fn signed_fetch(
        &self,
        stream: &mut TcpStream,
        query: ObserverQuery,
    ) -> Result<CouncilResponse> {
        write_frame_blocking(stream, &CouncilRequest::ObserverChallenge)
            .context("requesting challenge")?;
        let nonce = match read_frame_blocking(stream).context("reading challenge")? {
            Some(CouncilResponse::Challenge { nonce }) => nonce,
            Some(other) => bail!("parent refused the challenge: {}", describe(&other)),
            None => bail!("parent closed the connection on the challenge"),
        };

        let request = ObserverFetchRequest {
            network_id: *self.network_id.as_bytes(),
            observer_index: self.observer_index,
            query,
        };
        let payload = observer_fetch_signing_payload(&nonce, &request)
            .context("encoding fetch for signing")?;
        let signature = self.signer.sign(&payload);
        write_frame_blocking(
            stream,
            &CouncilRequest::ObserverFetch { request, signature },
        )
        .context("sending fetch")?;
        match read_frame_blocking(stream).context("reading fetch response")? {
            Some(response) => Ok(response),
            None => bail!("parent closed the connection on the fetch"),
        }
    }

    /// Fetch the parent's root key.
    pub fn fetch_root_key(&self) -> Result<Zeroizing<[u8; 32]>> {
        let mut stream = self.connect()?;
        match self.signed_fetch(&mut stream, ObserverQuery::RootKey)? {
            CouncilResponse::RootKey(root) => Ok(Zeroizing::new(root.key)),
            other => bail!("parent refused the root key: {}", describe(&other)),
        }
    }

    /// Close the delivery gap: page epoch-root envelopes from the local max
    /// upward and install each through `state.deliver()` (which re-verifies
    /// the council signature and persists). Returns the parent's highest
    /// delivered epoch.
    fn sync(&self, state: &CentralizedCustodianState) -> Result<u64> {
        let mut stream = self.connect()?;
        loop {
            let local = state.status().epoch;
            let response = self.signed_fetch(
                &mut stream,
                ObserverQuery::Envelopes {
                    from_epoch: local + 1,
                },
            )?;
            let (envelopes, delivered_epoch) = match response {
                CouncilResponse::Envelopes {
                    envelopes,
                    delivered_epoch,
                } => (envelopes, delivered_epoch),
                other => bail!("parent refused envelopes: {}", describe(&other)),
            };
            if local >= delivered_epoch {
                return Ok(delivered_epoch);
            }
            if envelopes.is_empty() {
                bail!(
                    "parent reports {delivered_epoch} epochs but sent none from {}",
                    local + 1
                );
            }
            for envelope in &envelopes {
                match state.deliver(envelope) {
                    CouncilResponse::Delivered { .. }
                    | CouncilResponse::AlreadyDelivered { .. } => {}
                    CouncilResponse::Rejected { code, message } => bail!(
                        "parent-forwarded envelope for epoch {} rejected ({code:?}): {message}",
                        envelope.payload.epoch,
                    ),
                    other => bail!("unexpected deliver outcome: {}", other.kind()),
                }
            }
            let after = state.status().epoch;
            if after <= local {
                bail!("no progress installing envelopes (local epoch stuck at {local})");
            }
            if after >= delivered_epoch {
                return Ok(delivered_epoch);
            }
        }
    }

    /// Boot-time backfill: bring the epoch sequence up to the parent's
    /// delivered epoch. Failures are returned, not fatal — the caller
    /// decides (boot warns and relies on on-demand fetches to heal later).
    pub fn backfill(&self, state: &CentralizedCustodianState) -> Result<()> {
        let _serialized = lock(&self.fetch_lock);
        let delivered = self.sync(state).context("backfilling epoch roots")?;
        info!(delivered, "backfilled from parent custodian");
        Ok(())
    }

    /// On-demand: try to close the gap up to `target_epoch`. `Ok(true)` if
    /// the epoch is now installed locally, `Ok(false)` if the parent doesn't
    /// have it either.
    pub fn fetch_up_to(
        &self,
        state: &CentralizedCustodianState,
        target_epoch: u64,
    ) -> Result<bool> {
        let _serialized = lock(&self.fetch_lock);
        // A racing handler may have closed the gap while we waited.
        if state.status().epoch >= target_epoch {
            return Ok(true);
        }
        self.sync(state)?;
        Ok(state.status().epoch >= target_epoch)
    }
}

fn lock(mutex: &Mutex<()>) -> std::sync::MutexGuard<'_, ()> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Log-friendly description of an unexpected response; never includes key
/// material (rejections carry only sanitized text).
fn describe(response: &CouncilResponse) -> String {
    match response {
        CouncilResponse::ObserverRejected { code, message } => {
            format!("{code:?}: {message}")
        }
        other => other.kind().to_string(),
    }
}

/// The observer-mode root key at boot.
///
/// - Local keyfile present: cross-check against the parent's. A mismatch is
///   FATAL — an observer silently serving epoch-0 keys derived from a
///   different root would diverge from its parent undetectably. If the
///   parent is unreachable, warn and continue with the local key.
/// - No local keyfile: the parent's copy is required (fatal if unreachable)
///   and is persisted durably before use.
///
/// Never pins the public default: an observer's root key is defined by its
/// parent.
pub fn obtain_root_key(fetcher: &ParentFetcher, root_key_path: &Path) -> Result<[u8; 32]> {
    match root_key_file::load_existing(root_key_path)? {
        Some(local) => {
            match fetcher.fetch_root_key() {
                Ok(parent) => {
                    if *parent != local {
                        bail!(
                            "root key at {} does not match the parent custodian's; \
                             refusing to serve divergent epoch-0 keys",
                            root_key_path.display()
                        );
                    }
                    info!("local root key matches the parent custodian");
                }
                Err(e) => warn!(
                    error = %format!("{e:#}"),
                    "parent unreachable for root-key cross-check; continuing with the local key"
                ),
            }
            Ok(local)
        }
        None => {
            let parent = fetcher
                .fetch_root_key()
                .context("no local root key and the parent custodian is unreachable")?;
            root_key_file::write_new(root_key_path, &parent)?;
            info!(path = %root_key_path.display(), "root key fetched from parent and persisted");
            Ok(*parent)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::council::serve_council;
    use crate::test_support::{
        CHAIN_ID, EPOCH_ROOT, MASTER_SEED, ROOT_KEY, build_state, network_id, observer_serving,
        seal,
    };
    use seismic_council_delivery::MAX_ENVELOPES_PER_FETCH;
    use seismic_custodian::Custodian;
    use seismic_observer_key::observer_namespace_from_chain_id;
    use std::net::SocketAddr;
    use std::sync::Arc;

    /// A live parent custodian on 127.0.0.1: state + observer serving over
    /// real TCP. The returned state handle can keep receiving council
    /// deliveries mid-test.
    fn spawn_parent(dir: &Path) -> (SocketAddr, Arc<CentralizedCustodianState>) {
        let state = Arc::new(build_state(dir));
        let serving = Arc::new(observer_serving(dir));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind parent port");
        let addr = listener.local_addr().expect("parent addr");
        let council_state = state.clone();
        std::thread::spawn(move || serve_council(listener, council_state, Some(serving)));
        (addr, state)
    }

    fn fetcher(parent_addr: SocketAddr, index: u32) -> ParentFetcher {
        ParentFetcher::new(
            &MASTER_SEED,
            &observer_namespace_from_chain_id(CHAIN_ID),
            index,
            parent_addr.to_string(),
            network_id(),
        )
    }

    #[test]
    fn fetches_the_parents_root_key() {
        let parent_dir = tempfile::tempdir().unwrap();
        let (addr, _parent) = spawn_parent(parent_dir.path());
        let key = fetcher(addr, 0).fetch_root_key().expect("root key");
        assert_eq!(*key, ROOT_KEY);
    }

    #[test]
    fn backfill_installs_epoch_roots_and_pages_past_one_batch() {
        let parent_dir = tempfile::tempdir().unwrap();
        let (addr, parent) = spawn_parent(parent_dir.path());
        // More epochs than one fetch batch carries, so backfill must page.
        let epochs = (MAX_ENVELOPES_PER_FETCH + 3) as u64;
        for epoch in 1..=epochs {
            assert!(matches!(
                parent.deliver(&seal(epoch, EPOCH_ROOT)),
                CouncilResponse::Delivered { .. }
            ));
        }

        let observer_dir = tempfile::tempdir().unwrap();
        let observer = build_state(observer_dir.path());
        fetcher(addr, 0).backfill(&observer).expect("backfill");

        assert_eq!(observer.status().epoch, epochs);
        // Envelopes were re-verified and persisted: a restart still has them.
        let reloaded = build_state(observer_dir.path());
        assert_eq!(reloaded.status().epoch, epochs);
    }

    #[test]
    fn envelopes_failing_local_council_verification_abort_backfill() {
        let parent_dir = tempfile::tempdir().unwrap();
        let (addr, parent) = spawn_parent(parent_dir.path());
        assert!(matches!(
            parent.deliver(&seal(1, EPOCH_ROOT)),
            CouncilResponse::Delivered { .. }
        ));

        // An observer configured with a different council address must
        // reject the parent's envelopes — the parent is never trusted for
        // envelope contents.
        let observer_dir = tempfile::tempdir().unwrap();
        let observer = CentralizedCustodianState::new(
            Custodian::new(ROOT_KEY),
            observer_dir.path().join("deliveries"),
            [0xEE; 20],
            network_id(),
        )
        .unwrap();
        let error = fetcher(addr, 0).backfill(&observer).unwrap_err();
        assert!(
            format!("{error:#}").contains("BadSignature"),
            "unexpected error: {error:#}"
        );
        assert_eq!(observer.status().epoch, 0);
    }

    #[test]
    fn fetch_up_to_closes_the_gap_or_reports_unavailable() {
        let parent_dir = tempfile::tempdir().unwrap();
        let (addr, parent) = spawn_parent(parent_dir.path());
        let observer_dir = tempfile::tempdir().unwrap();
        let observer = build_state(observer_dir.path());
        let fetcher = fetcher(addr, 3);

        // Nothing delivered anywhere: the epoch is genuinely unavailable.
        assert!(!fetcher.fetch_up_to(&observer, 1).expect("fetch"));

        // Delivered at the parent only: the gap closes on demand.
        assert!(matches!(
            parent.deliver(&seal(1, EPOCH_ROOT)),
            CouncilResponse::Delivered { .. }
        ));
        assert!(fetcher.fetch_up_to(&observer, 1).expect("fetch"));
        assert_eq!(observer.status().epoch, 1);
    }

    #[test]
    fn dispatch_fetches_missing_epochs_from_the_parent() {
        use seismic_custodian_ipc::{Request, Response};

        let parent_dir = tempfile::tempdir().unwrap();
        let (addr, parent) = spawn_parent(parent_dir.path());
        assert!(matches!(
            parent.deliver(&seal(1, EPOCH_ROOT)),
            CouncilResponse::Delivered { .. }
        ));

        let observer_dir = tempfile::tempdir().unwrap();
        let observer = build_state(observer_dir.path());
        let fetcher = fetcher(addr, 0);

        // Delivered only at the parent: the observer's socket still serves
        // it, deriving the tx-io key from the fetched epoch root.
        let response = crate::dispatch::dispatch(
            &observer,
            Some(&fetcher),
            Request::GetTxIoKeypair { epoch: 1 },
        );
        let Response::TxIoKeypair(keys) = response else {
            panic!("expected tx-io keypair, got {}", response.kind());
        };
        assert_eq!(
            keys.sk,
            Custodian::new(EPOCH_ROOT).get_tx_io_sk(1).secret_bytes()
        );

        // An epoch the parent doesn't have either stays a typed error.
        let response = crate::dispatch::dispatch(
            &observer,
            Some(&fetcher),
            Request::GetTxIoKeypair { epoch: 5 },
        );
        assert!(matches!(
            response,
            Response::EpochKeyUnavailable { epoch: 5 }
        ));
    }

    #[test]
    fn dispatch_degrades_to_unavailable_when_the_parent_is_down() {
        use seismic_custodian_ipc::{Request, Response};

        let observer_dir = tempfile::tempdir().unwrap();
        let observer = build_state(observer_dir.path());
        // A port nothing listens on: connect fails fast.
        let dead = ParentFetcher::new(
            &MASTER_SEED,
            &observer_namespace_from_chain_id(CHAIN_ID),
            0,
            "127.0.0.1:1".to_string(),
            network_id(),
        );
        let response =
            crate::dispatch::dispatch(&observer, Some(&dead), Request::GetTxIoKeypair { epoch: 1 });
        assert!(matches!(
            response,
            Response::EpochKeyUnavailable { epoch: 1 }
        ));
    }

    #[test]
    fn obtain_root_key_fetches_persists_and_cross_checks() {
        let parent_dir = tempfile::tempdir().unwrap();
        let (addr, _parent) = spawn_parent(parent_dir.path());
        let fetcher = fetcher(addr, 0);
        let observer_dir = tempfile::tempdir().unwrap();
        let path = observer_dir.path().join("root.key");

        // Absent: fetched from the parent and persisted (0600).
        assert_eq!(obtain_root_key(&fetcher, &path).unwrap(), ROOT_KEY);
        assert_eq!(std::fs::read(&path).unwrap(), ROOT_KEY);

        // Present and matching: fine on a re-boot.
        assert_eq!(obtain_root_key(&fetcher, &path).unwrap(), ROOT_KEY);

        // Present but different from the parent's: boot-fatal.
        std::fs::write(&path, [0xAA; 32]).unwrap();
        let error = obtain_root_key(&fetcher, &path).unwrap_err();
        assert!(
            error.to_string().contains("does not match the parent"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn obtain_root_key_without_a_reachable_parent() {
        let dead = ParentFetcher::new(
            &MASTER_SEED,
            &observer_namespace_from_chain_id(CHAIN_ID),
            0,
            "127.0.0.1:1".to_string(),
            network_id(),
        );
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("root.key");

        // No local key and no parent: fatal.
        assert!(obtain_root_key(&dead, &path).is_err());

        // A local key carries the boot with a warning.
        std::fs::write(&path, [0xBB; 32]).unwrap();
        assert_eq!(obtain_root_key(&dead, &path).unwrap(), [0xBB; 32]);
    }
}
