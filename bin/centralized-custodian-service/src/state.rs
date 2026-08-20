//! Council-delivered epoch keys over a locally persisted root key.
//!
//! This service runs standalone — the centralized phase before the network
//! moves to decentralized custody inside TEEs — so unlike
//! `seismic-custodian-service` there is no bootstrap flow, no LUKS handoff,
//! and no waiting on late-mounted storage: the root key is loaded (or
//! defaulted) from a keyfile before this state exists, and the delivery
//! store is scanned eagerly at construction, boot-fatally if its directory
//! is unusable.
//!
//! The [`EpochKeyStore`] holds per-purpose sequences of council-delivered
//! keys for epochs >= 1 (epoch 0 stays root-key-derived). Each delivery is
//! accepted only as a council-signed [`SignedDeliveryEnvelope`] and
//! persisted before it becomes observable, so a served key always survives
//! a restart. Envelopes carry the key in plaintext (transport
//! confidentiality is the deployment's TLS/tunnel in front of the port), so
//! the persisted files are themselves secrets: dirs 0700, files 0600.

use anyhow::{Context as _, Result};
use seismic_council_delivery::{
    CouncilResponse, CouncilStatus, DeliveryPurpose, RejectCode, SignedDeliveryEnvelope,
    VerifyDeliveryError, canonical_envelope_bytes, envelope_from_bytes, verify_delivery,
};
use seismic_custodian::{Custodian, Key};
use seismic_network_manifest::NetworkId;
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};
use tracing::{error, info, warn};
use zeroize::Zeroizing;

/// The host's one state slot: the custodian plus the delivered-key store.
pub struct CentralizedCustodianState {
    custodian: Custodian,
    deliveries: Mutex<EpochKeyStore>,
    delivery_dir: PathBuf,
    council_address: [u8; 20],
    network_id: NetworkId,
}

/// Council-delivered keys, one sequence per purpose: index `e - 1` holds
/// epoch `e`, so `len()` is the highest delivered epoch (0 = none delivered;
/// epoch 0 itself is always root-key-derived, never stored here).
#[derive(Default)]
struct EpochKeyStore {
    tx_io: Vec<StoredDelivery>,
    rng: Vec<StoredDelivery>,
    snapshot: Vec<StoredDelivery>,
}

struct StoredDelivery {
    key: Key,
    /// Canonical envelope CBOR — what is on disk; compared byte-for-byte to
    /// distinguish idempotent redelivery from an epoch conflict. Contains
    /// the plaintext key, hence zeroized.
    envelope_bytes: Zeroizing<Vec<u8>>,
}

impl EpochKeyStore {
    fn purpose(&self, purpose: DeliveryPurpose) -> &Vec<StoredDelivery> {
        match purpose {
            DeliveryPurpose::TxIo => &self.tx_io,
            DeliveryPurpose::RngPrecompile => &self.rng,
            DeliveryPurpose::Snapshot => &self.snapshot,
        }
    }

    fn purpose_mut(&mut self, purpose: DeliveryPurpose) -> &mut Vec<StoredDelivery> {
        match purpose {
            DeliveryPurpose::TxIo => &mut self.tx_io,
            DeliveryPurpose::RngPrecompile => &mut self.rng,
            DeliveryPurpose::Snapshot => &mut self.snapshot,
        }
    }
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

        let mut store = EpochKeyStore::default();
        for purpose in DeliveryPurpose::ALL {
            *store.purpose_mut(purpose) =
                load_purpose(&delivery_dir, purpose, &council_address, &network_id);
        }
        info!(
            tx_io = store.tx_io.len(),
            rng = store.rng.len(),
            snapshot = store.snapshot.len(),
            "delivery store loaded"
        );

        Ok(Self {
            custodian,
            deliveries: Mutex::new(store),
            delivery_dir,
            council_address,
            network_id,
        })
    }

    /// The custodian, for epoch-0 derivations.
    pub fn custodian(&self) -> &Custodian {
        &self.custodian
    }

    /// The deployment's network id (chain-id-derived in the centralized
    /// phase).
    pub fn network_id(&self) -> &NetworkId {
        &self.network_id
    }

    /// Handle one `DeliverEpochKey`. Verification order: envelope validity
    /// (network, signature), then sequencing, then key validity — and the
    /// envelope is durable on disk before the key becomes observable, so a
    /// served delivered key always survives a restart.
    pub fn deliver(&self, envelope: &SignedDeliveryEnvelope) -> CouncilResponse {
        let purpose = envelope.payload.purpose;
        let epoch = envelope.payload.epoch;

        let key_bytes = match verify_delivery(envelope, &self.council_address, &self.network_id) {
            Ok(key_bytes) => key_bytes,
            Err(e) => {
                warn!(?e, purpose = purpose.label(), epoch, "delivery refused");
                return rejected(verify_error_code(e), &e.to_string());
            }
        };

        let mut store = self.lock_deliveries();
        let sequence = store.purpose_mut(purpose);
        let max = sequence.len() as u64;
        if (1..=max).contains(&epoch) {
            let existing = &sequence[(epoch - 1) as usize];
            let incoming = match canonical_envelope_bytes(envelope) {
                Ok(bytes) => bytes,
                Err(e) => {
                    error!(?e, "encoding incoming envelope for identity check");
                    return rejected(RejectCode::EpochConflict, "envelope comparison failed");
                }
            };
            return if *existing.envelope_bytes == *incoming {
                CouncilResponse::AlreadyDelivered { purpose, epoch }
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

        let key = Key::new(*key_bytes);
        if !key_is_valid_for(&key, purpose) {
            warn!(purpose = purpose.label(), epoch, "delivered key unusable");
            return rejected(RejectCode::InvalidKey, "key is not usable for this purpose");
        }

        let envelope_bytes = match canonical_envelope_bytes(envelope) {
            Ok(bytes) => bytes,
            Err(e) => {
                error!(?e, "encoding envelope for persistence");
                return rejected(RejectCode::PersistFailed, "envelope encoding failed");
            }
        };
        if let Err(e) = persist_envelope(&self.delivery_dir, purpose, epoch, &envelope_bytes) {
            error!(?e, purpose = purpose.label(), epoch, "persisting delivery");
            return rejected(
                RejectCode::PersistFailed,
                "delivery could not be made durable; nothing was installed",
            );
        }

        sequence.push(StoredDelivery {
            key,
            envelope_bytes,
        });
        info!(purpose = purpose.label(), epoch, "epoch key delivered");
        CouncilResponse::Delivered { purpose, epoch }
    }

    /// Public delivery state: what the council needs to seal the next
    /// envelope.
    pub fn status(&self) -> CouncilStatus {
        let store = self.lock_deliveries();
        CouncilStatus {
            network_id: *self.network_id.as_bytes(),
            tx_io_epoch: store.tx_io.len() as u64,
            rng_epoch: store.rng.len() as u64,
            snapshot_epoch: store.snapshot.len() as u64,
        }
    }

    /// Run `f` against the delivered key for `(purpose, epoch)`, or `None`
    /// if that epoch has not been delivered. Callers route epoch 0 to the
    /// custodian's derivation, never here.
    pub fn with_epoch_key<T>(
        &self,
        purpose: DeliveryPurpose,
        epoch: u64,
        f: impl FnOnce(&Key) -> T,
    ) -> Option<T> {
        debug_assert!(epoch >= 1, "epoch 0 is derived, not delivered");
        if epoch == 0 {
            return None;
        }
        let store = self.lock_deliveries();
        store
            .purpose(purpose)
            .get((epoch - 1) as usize)
            .map(|stored| f(&stored.key))
    }

    /// Decoded envelopes for `purpose`, epochs ascending from `from_epoch`,
    /// at most `max` — plus the highest delivered epoch, so an observer
    /// knows whether to page again. Decodes the stored canonical bytes,
    /// which were signature-verified at delivery or load time; a decode
    /// failure here is defensive only (log and stop the batch early).
    pub fn envelopes_from(
        &self,
        purpose: DeliveryPurpose,
        from_epoch: u64,
        max: usize,
    ) -> (Vec<SignedDeliveryEnvelope>, u64) {
        let store = self.lock_deliveries();
        let sequence = store.purpose(purpose);
        let delivered_epoch = sequence.len() as u64;
        let first = from_epoch.max(1);
        let mut envelopes = Vec::new();
        for stored in sequence.iter().skip((first - 1) as usize).take(max) {
            match envelope_from_bytes(&stored.envelope_bytes) {
                Ok(envelope) => envelopes.push(envelope),
                Err(e) => {
                    error!(?e, purpose = purpose.label(), "stored envelope undecodable");
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

/// Load `1.cbor, 2.cbor, ...` for one purpose, stopping at the first gap. A
/// file that fails verification stops the scan at the last good epoch —
/// deliberately not boot-fatal, because a byte-faithful redelivery of that
/// epoch heals it (persist renames over the bad file) while a fatal error
/// would keep the service down.
fn load_purpose(
    delivery_dir: &Path,
    purpose: DeliveryPurpose,
    council_address: &[u8; 20],
    network_id: &NetworkId,
) -> Vec<StoredDelivery> {
    let mut sequence = Vec::new();
    for epoch in 1u64.. {
        let path = envelope_path(delivery_dir, purpose, epoch);
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
                if envelope.payload.purpose != purpose || envelope.payload.epoch != epoch {
                    return Err("purpose/epoch does not match its path".into());
                }
                verify_delivery(&envelope, council_address, network_id)
                    .map_err(|e| format!("verify: {e}"))
            })
            .and_then(|key_bytes| {
                let key = Key::new(*key_bytes);
                key_is_valid_for(&key, purpose)
                    .then_some(key)
                    .ok_or_else(|| "key unusable for purpose".into())
            });
        match stored {
            Ok(key) => sequence.push(StoredDelivery {
                key,
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
    sequence
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

/// A delivered key must convert cleanly now so serving it can never panic
/// later.
fn key_is_valid_for(key: &Key, purpose: DeliveryPurpose) -> bool {
    match purpose {
        DeliveryPurpose::TxIo => key.to_secp256k1_keypair().is_ok(),
        DeliveryPurpose::RngPrecompile => key.to_rng_ikm().is_ok(),
        DeliveryPurpose::Snapshot => true,
    }
}

fn envelope_path(delivery_dir: &Path, purpose: DeliveryPurpose, epoch: u64) -> PathBuf {
    delivery_dir
        .join(purpose.label())
        .join(format!("{epoch}.cbor"))
}

/// Durably write one envelope: tmp sibling + fsync + rename over the final
/// name + directory fsync (the same pattern the TDX custodian uses for its
/// LUKS keyfile). Rename-over, not `create_new`, so redelivery can heal a
/// corrupt earlier file. Mode 0600: the file contains the plaintext key.
fn persist_envelope(
    delivery_dir: &Path,
    purpose: DeliveryPurpose,
    epoch: u64,
    envelope_bytes: &[u8],
) -> Result<()> {
    let purpose_dir = delivery_dir.join(purpose.label());
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&purpose_dir)
        .with_context(|| format!("creating {}", purpose_dir.display()))?;

    let final_path = purpose_dir.join(format!("{epoch}.cbor"));
    let tmp_path = purpose_dir.join(format!("{epoch}.cbor.tmp"));
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
    fs::File::open(&purpose_dir)
        .and_then(|dir| dir.sync_all())
        .context("syncing delivery directory")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{NETWORK, PURPOSE_KEY, ROOT_KEY, build_state, council_keys, seal};
    use seismic_council_delivery::seal_delivery;
    use std::os::unix::fs::PermissionsExt as _;

    fn assert_delivered(response: &CouncilResponse, epoch: u64) {
        assert!(
            matches!(response, CouncilResponse::Delivered { epoch: e, .. } if *e == epoch),
            "expected Delivered {{ epoch: {epoch} }}, got {response:?}"
        );
    }

    fn assert_rejected(response: &CouncilResponse, code: RejectCode) {
        assert!(
            matches!(response, CouncilResponse::Rejected { code: c, .. } if *c == code),
            "expected Rejected {{ {code:?} }}, got {response:?}"
        );
    }

    fn epoch_key(
        state: &CentralizedCustodianState,
        purpose: DeliveryPurpose,
        epoch: u64,
    ) -> Option<[u8; 32]> {
        state.with_epoch_key(purpose, epoch, |key| {
            key.as_ref().try_into().expect("32 bytes")
        })
    }

    #[test]
    fn sequential_deliveries_install_and_serve() {
        let dir = tempfile::tempdir().unwrap();
        let state = build_state(dir.path());
        for epoch in 1..=3u64 {
            let key = [epoch as u8; 32];
            let response = state.deliver(&seal(DeliveryPurpose::TxIo, epoch, key));
            assert_delivered(&response, epoch);
            assert_eq!(epoch_key(&state, DeliveryPurpose::TxIo, epoch), Some(key));
        }
        // Purposes sequence independently.
        assert_delivered(
            &state.deliver(&seal(DeliveryPurpose::Snapshot, 1, PURPOSE_KEY)),
            1,
        );
        let status = state.status();
        assert_eq!(status.tx_io_epoch, 3);
        assert_eq!(status.snapshot_epoch, 1);
        assert_eq!(status.rng_epoch, 0);
        assert_eq!(status.network_id, NETWORK);
    }

    #[test]
    fn non_sequential_epochs_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let state = build_state(dir.path());
        assert_rejected(
            &state.deliver(&seal(DeliveryPurpose::TxIo, 2, PURPOSE_KEY)),
            RejectCode::NonSequentialEpoch,
        );
        assert_rejected(
            &state.deliver(&seal(DeliveryPurpose::TxIo, 0, PURPOSE_KEY)),
            RejectCode::NonSequentialEpoch,
        );
        assert_delivered(
            &state.deliver(&seal(DeliveryPurpose::TxIo, 1, PURPOSE_KEY)),
            1,
        );
        assert_rejected(
            &state.deliver(&seal(DeliveryPurpose::TxIo, 3, PURPOSE_KEY)),
            RejectCode::NonSequentialEpoch,
        );
    }

    #[test]
    fn redelivery_is_idempotent_but_a_different_key_conflicts() {
        let dir = tempfile::tempdir().unwrap();
        let state = build_state(dir.path());
        let envelope = seal(DeliveryPurpose::TxIo, 1, PURPOSE_KEY);
        assert_delivered(&state.deliver(&envelope), 1);
        assert!(matches!(
            state.deliver(&envelope),
            CouncilResponse::AlreadyDelivered { epoch: 1, .. }
        ));
        // Sealing is deterministic, so even a from-scratch re-seal of the
        // same key is the identical envelope: idempotent.
        assert!(matches!(
            state.deliver(&seal(DeliveryPurpose::TxIo, 1, PURPOSE_KEY)),
            CouncilResponse::AlreadyDelivered { epoch: 1, .. }
        ));
        // A *different* key at an installed epoch is a conflict.
        assert_rejected(
            &state.deliver(&seal(DeliveryPurpose::TxIo, 1, [0x43; 32])),
            RejectCode::EpochConflict,
        );
        // The original still serves.
        assert_eq!(
            epoch_key(&state, DeliveryPurpose::TxIo, 1),
            Some(PURPOSE_KEY)
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
            DeliveryPurpose::TxIo,
            1,
            &PURPOSE_KEY,
        );
        assert_rejected(&state.deliver(&foreign), RejectCode::WrongNetwork);

        // Signed by an impostor key.
        let impostor = secp256k1::SecretKey::from_byte_array(&[0x66; 32]).unwrap();
        let forged = seal_delivery(
            &impostor,
            &state.network_id,
            DeliveryPurpose::TxIo,
            1,
            &PURPOSE_KEY,
        );
        assert_rejected(&state.deliver(&forged), RejectCode::BadSignature);

        // A key that is not a secp256k1 scalar cannot serve tx-io.
        assert_rejected(
            &state.deliver(&seal(DeliveryPurpose::TxIo, 1, [0xff; 32])),
            RejectCode::InvalidKey,
        );
        // ...but is fine as a snapshot key (any 32 bytes).
        assert_delivered(
            &state.deliver(&seal(DeliveryPurpose::Snapshot, 1, [0xff; 32])),
            1,
        );
        // Nothing was installed for tx-io by the failures above.
        assert_eq!(state.status().tx_io_epoch, 0);
    }

    #[test]
    fn unpersistable_delivery_installs_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let state = build_state(dir.path());
        assert_delivered(
            &state.deliver(&seal(DeliveryPurpose::TxIo, 1, PURPOSE_KEY)),
            1,
        );

        // Make the purpose directory unwritable; epoch 2 must fail closed.
        let purpose_dir = dir.path().join("deliveries").join("tx-io");
        fs::set_permissions(&purpose_dir, fs::Permissions::from_mode(0o500)).unwrap();
        assert_rejected(
            &state.deliver(&seal(DeliveryPurpose::TxIo, 2, PURPOSE_KEY)),
            RejectCode::PersistFailed,
        );
        assert!(epoch_key(&state, DeliveryPurpose::TxIo, 2).is_none());
        assert_eq!(state.status().tx_io_epoch, 1);

        // Restored, the same delivery succeeds.
        fs::set_permissions(&purpose_dir, fs::Permissions::from_mode(0o700)).unwrap();
        assert_delivered(
            &state.deliver(&seal(DeliveryPurpose::TxIo, 2, PURPOSE_KEY)),
            2,
        );
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
        let keys: Vec<[u8; 32]> = (1..=3u8).map(|e| [e; 32]).collect();
        {
            let state = build_state(dir.path());
            for (i, key) in keys.iter().enumerate() {
                assert_delivered(
                    &state.deliver(&seal(DeliveryPurpose::TxIo, (i + 1) as u64, *key)),
                    (i + 1) as u64,
                );
            }
        }
        // "Restart": a fresh state over the same directories.
        let state = build_state(dir.path());
        let status = state.status();
        assert_eq!(status.tx_io_epoch, 3);
        for (i, key) in keys.iter().enumerate() {
            assert_eq!(
                epoch_key(&state, DeliveryPurpose::TxIo, (i + 1) as u64),
                Some(*key)
            );
        }
        // The sequence continues where it left off.
        assert_delivered(
            &state.deliver(&seal(DeliveryPurpose::TxIo, 4, PURPOSE_KEY)),
            4,
        );
    }

    #[test]
    fn corrupt_stored_epoch_serves_prefix_and_heals_by_redelivery() {
        let dir = tempfile::tempdir().unwrap();
        let envelope2 = seal(DeliveryPurpose::TxIo, 2, [2; 32]);
        {
            let state = build_state(dir.path());
            assert_delivered(&state.deliver(&seal(DeliveryPurpose::TxIo, 1, [1; 32])), 1);
            assert_delivered(&state.deliver(&envelope2), 2);
            assert_delivered(&state.deliver(&seal(DeliveryPurpose::TxIo, 3, [3; 32])), 3);
        }
        let epoch2_path = dir.path().join("deliveries/tx-io/2.cbor");
        fs::write(&epoch2_path, b"corrupted").unwrap();

        // Restart: the scan stops at the last good epoch before the damage.
        let state = build_state(dir.path());
        assert_eq!(state.status().tx_io_epoch, 1);
        assert_eq!(epoch_key(&state, DeliveryPurpose::TxIo, 1), Some([1; 32]));
        assert!(epoch_key(&state, DeliveryPurpose::TxIo, 2).is_none());

        // Redelivering the original envelope heals epoch 2 (rename-over)...
        assert_delivered(&state.deliver(&envelope2), 2);
        assert_eq!(epoch_key(&state, DeliveryPurpose::TxIo, 2), Some([2; 32]));

        // ...and epoch 3's file was never touched, so another restart
        // recovers the full sequence.
        let state = build_state(dir.path());
        assert_eq!(state.status().tx_io_epoch, 3);
        assert_eq!(epoch_key(&state, DeliveryPurpose::TxIo, 3), Some([3; 32]));
    }
}
