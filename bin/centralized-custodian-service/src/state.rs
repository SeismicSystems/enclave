//! Council-delivered epoch root keys over a locally persisted epoch-0 root.
//!
//! This service runs standalone — the centralized phase before the network
//! moves to decentralized custody inside TEEs — so unlike
//! `seismic-custodian-service` there is no bootstrap flow, no LUKS handoff,
//! and no waiting on late-mounted storage: the epoch-0 root key is loaded
//! (or defaulted) from a keyfile before this state exists, and the delivery
//! store is scanned eagerly at construction, boot-fatally if its directory
//! is unusable.
//!
//! Rotation model: the council delivers one 32-byte ROOT key per epoch, and
//! every purpose key of that epoch (tx-io, rng, snapshot) is HKDF-derived
//! from it — the exact derivation epoch 0 uses on the keyfile root. The
//! [`EpochKeyStore`] holds one [`Custodian`] per delivered epoch. Each
//! delivery is accepted only as a council-signed [`SignedDeliveryEnvelope`]
//! and persisted before it becomes observable, so a served key always
//! survives a restart. Envelopes carry the root key in plaintext (transport
//! confidentiality is the deployment's TLS/tunnel in front of the port), so
//! the persisted files are themselves secrets: dirs 0700, files 0600.

use anyhow::{Context as _, Result};
use seismic_council_delivery::{
    CouncilResponse, CouncilStatus, RejectCode, SignedDeliveryEnvelope, VerifyDeliveryError,
    canonical_envelope_bytes, envelope_from_bytes, verify_delivery,
};
use seismic_custodian::{Custodian, KeyPurpose};
use seismic_network_manifest::NetworkId;
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};
use tracing::{error, info, warn};
use zeroize::Zeroizing;

/// The host's one state slot: the epoch-0 custodian plus the delivered
/// epoch-root store.
pub struct CentralizedCustodianState {
    custodian: Custodian,
    deliveries: Mutex<EpochKeyStore>,
    delivery_dir: PathBuf,
    council_address: [u8; 20],
    network_id: NetworkId,
}

/// Council-delivered epoch roots: index `e - 1` holds epoch `e`, so `len()`
/// is the highest delivered epoch (0 = none delivered; epoch 0 itself is
/// always keyfile-derived, never stored here).
#[derive(Default)]
struct EpochKeyStore {
    epochs: Vec<StoredDelivery>,
}

struct StoredDelivery {
    /// A custodian over the delivered epoch root: purpose keys for this
    /// epoch derive from it exactly as epoch 0 derives from the keyfile.
    custodian: Custodian,
    /// Canonical envelope CBOR — what is on disk; compared byte-for-byte to
    /// distinguish idempotent redelivery from an epoch conflict. Contains
    /// the plaintext root key, hence zeroized.
    envelope_bytes: Zeroizing<Vec<u8>>,
}

impl CentralizedCustodianState {
    /// Build the state, eagerly loading every persisted delivery. Errors
    /// (boot-fatally, by design) if the delivery directory cannot be
    /// created; individual damaged files are *not* fatal — the scan stops at
    /// the last good epoch and a redelivery heals it.
    pub fn new(
        custodian: Custodian,
        delivery_dir: PathBuf,
        council_address: [u8; 20],
        network_id: NetworkId,
    ) -> Result<Self> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&delivery_dir)
            .with_context(|| format!("creating delivery dir {}", delivery_dir.display()))?;

        let store = EpochKeyStore {
            epochs: load_epochs(&delivery_dir, &council_address, &network_id),
        };
        info!(epoch = store.epochs.len(), "delivery store loaded");

        Ok(Self {
            custodian,
            deliveries: Mutex::new(store),
            delivery_dir,
            council_address,
            network_id,
        })
    }

    /// The custodian for epoch-0 derivations (the keyfile root).
    pub fn custodian(&self) -> &Custodian {
        &self.custodian
    }

    /// The deployment's network id (chain-id-derived in the centralized
    /// phase).
    pub fn network_id(&self) -> &NetworkId {
        &self.network_id
    }

    /// Handle one `DeliverEpochKey`. Verification order: envelope validity
    /// (network, signature), then sequencing, then derived-key validity —
    /// and the envelope is durable on disk before the root becomes
    /// observable, so a served epoch always survives a restart.
    pub fn deliver(&self, envelope: &SignedDeliveryEnvelope) -> CouncilResponse {
        let epoch = envelope.payload.epoch;

        let root = match verify_delivery(envelope, &self.council_address, &self.network_id) {
            Ok(root) => root,
            Err(e) => {
                warn!(?e, epoch, "delivery refused");
                return rejected(verify_error_code(e), &e.to_string());
            }
        };

        let mut store = self.lock_deliveries();
        let max = store.epochs.len() as u64;
        if (1..=max).contains(&epoch) {
            let existing = &store.epochs[(epoch - 1) as usize];
            let incoming = match canonical_envelope_bytes(envelope) {
                Ok(bytes) => bytes,
                Err(e) => {
                    error!(?e, "encoding incoming envelope for identity check");
                    return rejected(RejectCode::EpochConflict, "envelope comparison failed");
                }
            };
            return if *existing.envelope_bytes == *incoming {
                CouncilResponse::AlreadyDelivered { epoch }
            } else {
                rejected(
                    RejectCode::EpochConflict,
                    &format!("a different envelope already holds epoch {epoch}"),
                )
            };
        }
        if epoch != max + 1 {
            return rejected(
                RejectCode::NonSequentialEpoch,
                &format!("expected epoch {}, got {epoch}", max + 1),
            );
        }

        let custodian = Custodian::new(*root);
        if !root_serves_all_purposes(&custodian, epoch) {
            warn!(epoch, "delivered root derives an unusable purpose key");
            return rejected(
                RejectCode::InvalidKey,
                "a purpose key derived from this root is unusable",
            );
        }

        let envelope_bytes = match canonical_envelope_bytes(envelope) {
            Ok(bytes) => bytes,
            Err(e) => {
                error!(?e, "encoding envelope for persistence");
                return rejected(RejectCode::PersistFailed, "envelope encoding failed");
            }
        };
        if let Err(e) = persist_envelope(&self.delivery_dir, epoch, &envelope_bytes) {
            error!(?e, epoch, "persisting delivery");
            return rejected(
                RejectCode::PersistFailed,
                "delivery could not be made durable; nothing was installed",
            );
        }

        store.epochs.push(StoredDelivery {
            custodian,
            envelope_bytes,
        });
        info!(epoch, "epoch root key delivered");
        CouncilResponse::Delivered { epoch }
    }

    /// Public delivery state: what the council needs to seal the next
    /// envelope.
    pub fn status(&self) -> CouncilStatus {
        let store = self.lock_deliveries();
        CouncilStatus {
            network_id: *self.network_id.as_bytes(),
            epoch: store.epochs.len() as u64,
        }
    }

    /// Run `f` against the custodian holding the delivered root for `epoch`,
    /// or `None` if that epoch has not been delivered. Callers route epoch 0
    /// to [`Self::custodian`], never here.
    pub fn with_epoch_custodian<T>(
        &self,
        epoch: u64,
        f: impl FnOnce(&Custodian) -> T,
    ) -> Option<T> {
        debug_assert!(epoch >= 1, "epoch 0 is keyfile-derived, not delivered");
        if epoch == 0 {
            return None;
        }
        let store = self.lock_deliveries();
        store
            .epochs
            .get((epoch - 1) as usize)
            .map(|stored| f(&stored.custodian))
    }

    /// Decoded envelopes for epochs ascending from `from_epoch`, at most
    /// `max` — plus the highest delivered epoch, so an observer knows
    /// whether to page again. Decodes the stored canonical bytes, which were
    /// signature-verified at delivery or load time; a decode failure here is
    /// defensive only (log and stop the batch early).
    pub fn envelopes_from(
        &self,
        from_epoch: u64,
        max: usize,
    ) -> (Vec<SignedDeliveryEnvelope>, u64) {
        let store = self.lock_deliveries();
        let delivered_epoch = store.epochs.len() as u64;
        let first = from_epoch.max(1);
        let mut envelopes = Vec::new();
        for stored in store.epochs.iter().skip((first - 1) as usize).take(max) {
            match envelope_from_bytes(&stored.envelope_bytes) {
                Ok(envelope) => envelopes.push(envelope),
                Err(e) => {
                    error!(?e, "stored envelope undecodable");
                    break;
                }
            }
        }
        (envelopes, delivered_epoch)
    }

    fn lock_deliveries(&self) -> MutexGuard<'_, EpochKeyStore> {
        // Poison-recovering: every mutation is a whole push, so no torn
        // state is observable.
        self.deliveries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

/// Load `1.cbor, 2.cbor, ...`, stopping at the first gap. A file that fails
/// verification stops the scan at the last good epoch — deliberately not
/// boot-fatal, because a byte-faithful redelivery of that epoch heals it
/// (persist renames over the bad file) while a fatal error would keep the
/// service down.
fn load_epochs(
    delivery_dir: &Path,
    council_address: &[u8; 20],
    network_id: &NetworkId,
) -> Vec<StoredDelivery> {
    let mut epochs = Vec::new();
    for epoch in 1u64.. {
        let path = envelope_path(delivery_dir, epoch);
        let bytes = match fs::read(&path) {
            Ok(bytes) => Zeroizing::new(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
            Err(e) => {
                error!(?e, path = %path.display(), "unreadable stored delivery");
                break;
            }
        };
        let stored = envelope_from_bytes(&bytes)
            .map_err(|e| format!("decode: {e}"))
            .and_then(|envelope| {
                if envelope.payload.epoch != epoch {
                    return Err("epoch does not match its path".into());
                }
                verify_delivery(&envelope, council_address, network_id)
                    .map_err(|e| format!("verify: {e}"))
            })
            .and_then(|root| {
                let custodian = Custodian::new(*root);
                root_serves_all_purposes(&custodian, epoch)
                    .then_some(custodian)
                    .ok_or_else(|| "root derives an unusable purpose key".into())
            });
        match stored {
            Ok(custodian) => epochs.push(StoredDelivery {
                custodian,
                envelope_bytes: bytes,
            }),
            Err(reason) => {
                error!(
                    path = %path.display(),
                    reason,
                    "stored delivery failed verification; serving epochs below it \
                     (redeliver this epoch to heal)"
                );
                break;
            }
        }
    }
    epochs
}

fn rejected(code: RejectCode, message: &str) -> CouncilResponse {
    CouncilResponse::Rejected {
        code,
        message: message.to_string(),
    }
}

fn verify_error_code(e: VerifyDeliveryError) -> RejectCode {
    match e {
        VerifyDeliveryError::WrongNetwork => RejectCode::WrongNetwork,
        VerifyDeliveryError::BadSignature => RejectCode::BadSignature,
    }
}

/// Every purpose key this epoch will serve must derive and convert cleanly
/// now (astronomically unlikely to fail), so serving can never panic later.
fn root_serves_all_purposes(custodian: &Custodian, epoch: u64) -> bool {
    let tx_io = custodian
        .derive_purpose_key(KeyPurpose::TxIo, epoch)
        .is_ok_and(|key| key.to_secp256k1_keypair().is_ok());
    let rng = custodian
        .derive_purpose_key(KeyPurpose::RngPrecompile, epoch)
        .is_ok_and(|key| key.to_rng_ikm().is_ok());
    // Snapshot: any 32 bytes are a valid AES-256 key.
    tx_io && rng
}

fn envelope_path(delivery_dir: &Path, epoch: u64) -> PathBuf {
    delivery_dir.join(format!("{epoch}.cbor"))
}

/// Durably write one envelope: tmp sibling + fsync + rename over the final
/// name + directory fsync (the same pattern the TDX custodian uses for its
/// LUKS keyfile). Rename-over, not `create_new`, so redelivery can heal a
/// corrupt earlier file. Mode 0600: the file contains the plaintext root
/// key.
fn persist_envelope(delivery_dir: &Path, epoch: u64, envelope_bytes: &[u8]) -> Result<()> {
    let final_path = envelope_path(delivery_dir, epoch);
    let tmp_path = delivery_dir.join(format!("{epoch}.cbor.tmp"));
    match fs::remove_file(&tmp_path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).context("removing stale delivery tmp file"),
    }

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp_path)
        .with_context(|| format!("creating {}", tmp_path.display()))?;
    file.write_all(envelope_bytes)
        .context("writing delivery envelope")?;
    file.sync_all().context("syncing delivery envelope")?;
    drop(file);

    fs::rename(&tmp_path, &final_path)
        .with_context(|| format!("renaming into {}", final_path.display()))?;
    // Make the rename itself durable.
    fs::File::open(delivery_dir)
        .and_then(|dir| dir.sync_all())
        .context("syncing delivery directory")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{NETWORK, ROOT_KEY, build_state, council_keys, seal};
    use seismic_council_delivery::seal_delivery;
    use std::os::unix::fs::PermissionsExt as _;

    fn assert_delivered(response: &CouncilResponse, epoch: u64) {
        assert!(
            matches!(response, CouncilResponse::Delivered { epoch: e } if *e == epoch),
            "expected Delivered {{ epoch: {epoch} }}, got {response:?}"
        );
    }

    fn assert_rejected(response: &CouncilResponse, code: RejectCode) {
        assert!(
            matches!(response, CouncilResponse::Rejected { code: c, .. } if *c == code),
            "expected Rejected {{ {code:?} }}, got {response:?}"
        );
    }

    /// The tx-io secret an epoch serves, or None if undelivered.
    fn tx_io_sk(state: &CentralizedCustodianState, epoch: u64) -> Option<[u8; 32]> {
        state.with_epoch_custodian(epoch, |custodian| {
            custodian.get_tx_io_sk(epoch).secret_bytes()
        })
    }

    #[test]
    fn sequential_deliveries_install_and_derive_purpose_keys() {
        let dir = tempfile::tempdir().unwrap();
        let state = build_state(dir.path());
        for epoch in 1..=3u64 {
            let root = [epoch as u8; 32];
            let response = state.deliver(&seal(epoch, root));
            assert_delivered(&response, epoch);
            // Purpose keys derive from the delivered root exactly as a
            // custodian over that root would derive them.
            assert_eq!(
                tx_io_sk(&state, epoch),
                Some(Custodian::new(root).get_tx_io_sk(epoch).secret_bytes())
            );
        }
        let status = state.status();
        assert_eq!(status.epoch, 3);
        assert_eq!(status.network_id, NETWORK);
    }

    /// The same delivered root serves DIFFERENT purpose keys per purpose and
    /// per epoch (the epoch is bound into the derivation info).
    #[test]
    fn derivations_are_separated_by_purpose_and_epoch() {
        let root = [9u8; 32];
        let custodian = Custodian::new(root);
        let tx_io = custodian.get_tx_io_sk(1).secret_bytes();
        let rng = custodian.get_rng_ikm(1);
        let snapshot: [u8; 32] = custodian.get_snapshot_key(1).into();
        assert_ne!(tx_io.as_slice(), &rng[..32]);
        assert_ne!(tx_io, snapshot);
        // Same root at a different epoch derives different keys.
        assert_ne!(tx_io, custodian.get_tx_io_sk(2).secret_bytes());
    }

    #[test]
    fn non_sequential_epochs_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let state = build_state(dir.path());
        assert_rejected(
            &state.deliver(&seal(2, [2; 32])),
            RejectCode::NonSequentialEpoch,
        );
        assert_rejected(
            &state.deliver(&seal(0, [2; 32])),
            RejectCode::NonSequentialEpoch,
        );
        assert_delivered(&state.deliver(&seal(1, [1; 32])), 1);
        assert_rejected(
            &state.deliver(&seal(3, [3; 32])),
            RejectCode::NonSequentialEpoch,
        );
    }

    #[test]
    fn redelivery_is_idempotent_but_a_different_root_conflicts() {
        let dir = tempfile::tempdir().unwrap();
        let state = build_state(dir.path());
        let envelope = seal(1, [0x42; 32]);
        assert_delivered(&state.deliver(&envelope), 1);
        assert!(matches!(
            state.deliver(&envelope),
            CouncilResponse::AlreadyDelivered { epoch: 1 }
        ));
        // Sealing is deterministic, so even a from-scratch re-seal of the
        // same root is the identical envelope: idempotent.
        assert!(matches!(
            state.deliver(&seal(1, [0x42; 32])),
            CouncilResponse::AlreadyDelivered { epoch: 1 }
        ));
        // A *different* root at an installed epoch is a conflict.
        assert_rejected(
            &state.deliver(&seal(1, [0x43; 32])),
            RejectCode::EpochConflict,
        );
        // The original still serves.
        assert_eq!(
            tx_io_sk(&state, 1),
            Some(Custodian::new([0x42; 32]).get_tx_io_sk(1).secret_bytes())
        );
    }

    #[test]
    fn envelope_validation_failures_map_to_codes() {
        let dir = tempfile::tempdir().unwrap();
        let state = build_state(dir.path());

        // Wrong network.
        let foreign = seal_delivery(
            &council_keys().0,
            &NetworkId::from_bytes([0x99; 32]),
            1,
            &[0x42; 32],
        );
        assert_rejected(&state.deliver(&foreign), RejectCode::WrongNetwork);

        // Signed by an impostor key.
        let impostor = secp256k1::SecretKey::from_byte_array(&[0x66; 32]).unwrap();
        let forged = seal_delivery(&impostor, &state.network_id, 1, &[0x42; 32]);
        assert_rejected(&state.deliver(&forged), RejectCode::BadSignature);

        // Nothing was installed by the failures above.
        assert_eq!(state.status().epoch, 0);
    }

    #[test]
    fn unpersistable_delivery_installs_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let state = build_state(dir.path());
        assert_delivered(&state.deliver(&seal(1, [1; 32])), 1);

        // Make the delivery directory unwritable; epoch 2 must fail closed.
        let delivery_dir = dir.path().join("deliveries");
        fs::set_permissions(&delivery_dir, fs::Permissions::from_mode(0o500)).unwrap();
        assert_rejected(&state.deliver(&seal(2, [2; 32])), RejectCode::PersistFailed);
        assert!(tx_io_sk(&state, 2).is_none());
        assert_eq!(state.status().epoch, 1);

        // Restored, the same delivery succeeds.
        fs::set_permissions(&delivery_dir, fs::Permissions::from_mode(0o700)).unwrap();
        assert_delivered(&state.deliver(&seal(2, [2; 32])), 2);
    }

    #[test]
    fn unusable_delivery_dir_is_boot_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("not-a-dir");
        fs::write(&blocker, b"").unwrap();
        let result = CentralizedCustodianState::new(
            Custodian::new(ROOT_KEY),
            blocker.join("deliveries"),
            council_keys().1,
            crate::test_support::network_id(),
        );
        assert!(result.is_err(), "a blocked delivery dir must fail the boot");
    }

    #[test]
    fn restart_reloads_persisted_deliveries() {
        let dir = tempfile::tempdir().unwrap();
        let roots: Vec<[u8; 32]> = (1..=3u8).map(|e| [e; 32]).collect();
        {
            let state = build_state(dir.path());
            for (i, root) in roots.iter().enumerate() {
                assert_delivered(&state.deliver(&seal((i + 1) as u64, *root)), (i + 1) as u64);
            }
        }
        // "Restart": a fresh state over the same directories.
        let state = build_state(dir.path());
        assert_eq!(state.status().epoch, 3);
        for (i, root) in roots.iter().enumerate() {
            let epoch = (i + 1) as u64;
            assert_eq!(
                tx_io_sk(&state, epoch),
                Some(Custodian::new(*root).get_tx_io_sk(epoch).secret_bytes())
            );
        }
        // The sequence continues where it left off.
        assert_delivered(&state.deliver(&seal(4, [4; 32])), 4);
    }

    #[test]
    fn corrupt_stored_epoch_serves_prefix_and_heals_by_redelivery() {
        let dir = tempfile::tempdir().unwrap();
        let envelope2 = seal(2, [2; 32]);
        {
            let state = build_state(dir.path());
            assert_delivered(&state.deliver(&seal(1, [1; 32])), 1);
            assert_delivered(&state.deliver(&envelope2), 2);
            assert_delivered(&state.deliver(&seal(3, [3; 32])), 3);
        }
        let epoch2_path = dir.path().join("deliveries/2.cbor");
        fs::write(&epoch2_path, b"corrupted").unwrap();

        // Restart: the scan stops at the last good epoch before the damage.
        let state = build_state(dir.path());
        assert_eq!(state.status().epoch, 1);
        assert!(tx_io_sk(&state, 1).is_some());
        assert!(tx_io_sk(&state, 2).is_none());

        // Redelivering the original envelope heals epoch 2 (rename-over)...
        assert_delivered(&state.deliver(&envelope2), 2);
        assert!(tx_io_sk(&state, 2).is_some());

        // ...and epoch 3's file was never touched, so another restart
        // recovers the full sequence.
        let state = build_state(dir.path());
        assert_eq!(state.status().epoch, 3);
        assert!(tx_io_sk(&state, 3).is_some());
    }
}
