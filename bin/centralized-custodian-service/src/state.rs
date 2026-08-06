//! Council-delivered epoch keys layered over the base custodian state.
//!
//! The base [`CustodianState`] keeps its whole contract — root-key lifecycle,
//! bootstrap attempts, LUKS handoff, epoch-0 derivations. This module adds
//! the [`EpochKeyStore`]: per-purpose sequences of council-delivered keys for
//! epochs >= 1, each accepted only as a verified [`SignedDeliveryEnvelope`]
//! and persisted (as the envelope, never plaintext) before it becomes
//! observable — the same durability-before-visibility invariant the base
//! state keeps for the LUKS keyfile.
//!
//! Loading is lazy because of boot ordering: this very process writes the
//! LUKS keyfile that lets `setup-persistent-luks` mount the filesystem the
//! delivery store lives on, so the store is unreachable at process start.
//! Every entry point converges the store once its two preconditions hold
//! (root key present — the inbox key derives from it — and the delivery
//! directory creatable).

use anyhow::{Context as _, Result};
use secp256k1::{PublicKey, SecretKey};
use seismic_council_delivery::{
    CouncilResponse, CouncilStatus, DeliveryPurpose, InboxPk, OpenDeliveryError, RejectCode,
    SignedDeliveryEnvelope, canonical_envelope_bytes, envelope_from_bytes, open_delivery,
};
use seismic_custodian::Key;
use seismic_custodian_service::state::CustodianState;
use seismic_network_manifest::NetworkId;
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};
use tracing::{error, info, warn};

/// The host's one state slot: the base custodian plus the delivered-key store.
pub struct CentralizedCustodianState {
    base: CustodianState,
    deliveries: Mutex<EpochKeyStore>,
    delivery_dir: PathBuf,
    council_pk: PublicKey,
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
    /// One successful scan of the delivery directory happened; keys and disk
    /// agree from then on.
    loaded_from_disk: bool,
}

struct StoredDelivery {
    key: Key,
    /// Canonical envelope CBOR — what is on disk; compared byte-for-byte to
    /// distinguish idempotent redelivery from an epoch conflict. Ciphertext
    /// only, not secret.
    envelope_bytes: Vec<u8>,
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

/// Result of a unix-socket epoch-key lookup (epochs >= 1 only).
pub enum EpochKeyLookup<T> {
    Ok(T),
    /// The inbox key (and everything else) needs the root key first.
    RootKeyAbsent,
    /// No such delivered key — not delivered yet, or the store isn't
    /// reachable yet. Retriable either way.
    Unavailable,
}

/// Why [`CentralizedCustodianState::ensure_loaded`] couldn't converge.
enum LoadBlocked {
    RootKeyAbsent,
    PersistenceUnavailable,
}

impl CentralizedCustodianState {
    pub fn new(
        base: CustodianState,
        delivery_dir: PathBuf,
        council_pk: PublicKey,
        network_id: NetworkId,
    ) -> Self {
        Self {
            base,
            deliveries: Mutex::new(EpochKeyStore::default()),
            delivery_dir,
            council_pk,
            network_id,
        }
    }

    /// The base custodian state, for everything this module doesn't change:
    /// epoch-0 derivations, bootstrap methods, LUKS handoff.
    pub fn base(&self) -> &CustodianState {
        &self.base
    }

    /// Handle one `DeliverEpochKey`. Verification order: store preconditions,
    /// then envelope validity (network, recipient, signature, decrypt), then
    /// sequencing, then key validity — and the envelope is durable on disk
    /// before the key becomes observable, so a served delivered key always
    /// survives a restart.
    pub fn deliver(&self, envelope: &SignedDeliveryEnvelope) -> CouncilResponse {
        let mut store = self.lock_deliveries();
        let (inbox_sk, inbox_pk) = match self.ensure_loaded(&mut store) {
            Ok(keys) => keys,
            Err(blocked) => return blocked.into_rejection(),
        };

        let purpose = envelope.payload.purpose;
        let epoch = envelope.payload.epoch;

        let key_bytes = match open_delivery(
            envelope,
            &self.council_pk,
            &self.network_id,
            &inbox_sk,
            &inbox_pk,
        ) {
            Ok(key_bytes) => key_bytes,
            Err(e) => {
                warn!(?e, purpose = purpose.label(), epoch, "delivery refused");
                return rejected(open_error_code(e), &e.to_string());
            }
        };

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
            return if existing.envelope_bytes == incoming {
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
            return rejected(
                RejectCode::InvalidKey,
                "decrypted key is not usable for this purpose",
            );
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

    /// Public delivery state; always answers, even before the node can accept.
    pub fn status(&self) -> CouncilStatus {
        let mut store = self.lock_deliveries();
        let accepting_deliveries = self.ensure_loaded(&mut store).is_ok();
        let inbox_pk = self
            .base
            .with_custodian(|custodian| InboxPk(custodian.get_council_inbox_pk().serialize()));
        CouncilStatus {
            network_id: *self.network_id.as_bytes(),
            inbox_pk,
            tx_io_epoch: store.tx_io.len() as u64,
            rng_epoch: store.rng.len() as u64,
            snapshot_epoch: store.snapshot.len() as u64,
            accepting_deliveries,
        }
    }

    /// Run `f` against the delivered key for `(purpose, epoch)`. Callers
    /// route epoch 0 to the base custodian, never here.
    pub fn with_epoch_key<T>(
        &self,
        purpose: DeliveryPurpose,
        epoch: u64,
        f: impl FnOnce(&Key) -> T,
    ) -> EpochKeyLookup<T> {
        debug_assert!(epoch >= 1, "epoch 0 is derived, not delivered");
        if epoch == 0 {
            return EpochKeyLookup::Unavailable;
        }
        let mut store = self.lock_deliveries();
        match self.ensure_loaded(&mut store) {
            Ok(_) => {}
            Err(LoadBlocked::RootKeyAbsent) => return EpochKeyLookup::RootKeyAbsent,
            Err(LoadBlocked::PersistenceUnavailable) => return EpochKeyLookup::Unavailable,
        }
        match store.purpose(purpose).get((epoch - 1) as usize) {
            Some(stored) => EpochKeyLookup::Ok(f(&stored.key)),
            None => EpochKeyLookup::Unavailable,
        }
    }

    /// Converge the in-memory store with the on-disk envelopes once both
    /// preconditions hold; afterwards return the inbox keypair. Idempotent
    /// and cheap after the first success.
    fn ensure_loaded(
        &self,
        store: &mut MutexGuard<'_, EpochKeyStore>,
    ) -> Result<(SecretKey, PublicKey), LoadBlocked> {
        let Some((inbox_sk, inbox_pk)) = self.base.with_custodian(|custodian| {
            (
                custodian.get_council_inbox_sk(),
                custodian.get_council_inbox_pk(),
            )
        }) else {
            return Err(LoadBlocked::RootKeyAbsent);
        };
        if store.loaded_from_disk {
            return Ok((inbox_sk, inbox_pk));
        }

        if let Err(e) = fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.delivery_dir)
        {
            // ENOENT on an ancestor means the persistent filesystem is not
            // mounted yet — expected during boot, so log quietly.
            info!(
                ?e,
                dir = %self.delivery_dir.display(),
                "delivery store not reachable yet"
            );
            return Err(LoadBlocked::PersistenceUnavailable);
        }

        for purpose in DeliveryPurpose::ALL {
            let sequence = self.load_purpose(purpose, &inbox_sk, &inbox_pk);
            *store.purpose_mut(purpose) = sequence;
        }
        store.loaded_from_disk = true;
        info!(
            tx_io = store.tx_io.len(),
            rng = store.rng.len(),
            snapshot = store.snapshot.len(),
            "delivery store loaded"
        );
        Ok((inbox_sk, inbox_pk))
    }

    /// Load `1.cbor, 2.cbor, ...` for one purpose, stopping at the first
    /// gap. A file that fails verification stops the scan at the last good
    /// epoch — deliberately not fatal (this process also gates LUKS unlock
    /// for the whole node); a byte-faithful redelivery of that epoch heals it
    /// because persist renames over the bad file.
    fn load_purpose(
        &self,
        purpose: DeliveryPurpose,
        inbox_sk: &SecretKey,
        inbox_pk: &PublicKey,
    ) -> Vec<StoredDelivery> {
        let mut sequence = Vec::new();
        for epoch in 1u64.. {
            let path = envelope_path(&self.delivery_dir, purpose, epoch);
            let bytes = match fs::read(&path) {
                Ok(bytes) => bytes,
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
                    open_delivery(
                        &envelope,
                        &self.council_pk,
                        &self.network_id,
                        inbox_sk,
                        inbox_pk,
                    )
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

    fn lock_deliveries(&self) -> MutexGuard<'_, EpochKeyStore> {
        // Poison-recovering like the base state: every mutation is a whole
        // push or whole-vector assignment, so no torn state is observable.
        self.deliveries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

impl LoadBlocked {
    fn into_rejection(self) -> CouncilResponse {
        match self {
            LoadBlocked::RootKeyAbsent => rejected(
                RejectCode::RootKeyAbsent,
                "no root key yet; retry after bootstrap",
            ),
            LoadBlocked::PersistenceUnavailable => rejected(
                RejectCode::PersistenceUnavailable,
                "delivery store not mounted yet; retry",
            ),
        }
    }
}

fn rejected(code: RejectCode, message: &str) -> CouncilResponse {
    CouncilResponse::Rejected {
        code,
        message: message.to_string(),
    }
}

fn open_error_code(e: OpenDeliveryError) -> RejectCode {
    match e {
        OpenDeliveryError::WrongNetwork => RejectCode::WrongNetwork,
        OpenDeliveryError::WrongRecipient => RejectCode::WrongRecipient,
        OpenDeliveryError::BadSignature => RejectCode::BadSignature,
        OpenDeliveryError::DecryptFailed => RejectCode::DecryptFailed,
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
/// name + directory fsync (the `luks_keyfile.rs` pattern). Rename-over, not
/// `create_new`, so redelivery can heal a corrupt earlier file.
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
    use crate::test_support::{
        NETWORK, PURPOSE_KEY, ROOT_KEY, awaiting_state, council_keys, seal, state_with_root_key,
    };
    use seismic_council_delivery::seal_delivery;
    use seismic_custodian::Custodian;
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
        match state.with_epoch_key(purpose, epoch, |key| {
            key.as_ref().try_into().expect("32 bytes")
        }) {
            EpochKeyLookup::Ok(bytes) => Some(bytes),
            _ => None,
        }
    }

    #[test]
    fn sequential_deliveries_install_and_serve() {
        let dir = tempfile::tempdir().unwrap();
        let state = state_with_root_key(dir.path());
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
        assert!(status.accepting_deliveries);
        assert_eq!(status.network_id, NETWORK);
        assert!(status.inbox_pk.is_some());
    }

    #[test]
    fn non_sequential_epochs_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let state = state_with_root_key(dir.path());
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
    fn identical_redelivery_is_idempotent_but_conflicts_reject() {
        let dir = tempfile::tempdir().unwrap();
        let state = state_with_root_key(dir.path());
        let envelope = seal(DeliveryPurpose::TxIo, 1, PURPOSE_KEY);
        assert_delivered(&state.deliver(&envelope), 1);
        assert!(matches!(
            state.deliver(&envelope),
            CouncilResponse::AlreadyDelivered { epoch: 1, .. }
        ));
        // A fresh seal of the same key is a different envelope (fresh
        // ephemeral + nonce): conflict, by design.
        assert_rejected(
            &state.deliver(&seal(DeliveryPurpose::TxIo, 1, PURPOSE_KEY)),
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
        let state = state_with_root_key(dir.path());

        // Wrong network.
        let inbox_pk = Custodian::new(ROOT_KEY).get_council_inbox_pk();
        let foreign = seal_delivery(
            &council_keys().0,
            &NetworkId::from_bytes([0x99; 32]),
            DeliveryPurpose::TxIo,
            1,
            &inbox_pk,
            &PURPOSE_KEY,
        )
        .unwrap();
        assert_rejected(&state.deliver(&foreign), RejectCode::WrongNetwork);

        // Signed by an impostor key.
        let impostor = secp256k1::SecretKey::from_byte_array(&[0x66; 32]).unwrap();
        let forged = seal_delivery(
            &impostor,
            &state.network_id,
            DeliveryPurpose::TxIo,
            1,
            &inbox_pk,
            &PURPOSE_KEY,
        )
        .unwrap();
        assert_rejected(&state.deliver(&forged), RejectCode::BadSignature);

        // Sealed to someone else's inbox.
        let other_inbox = Custodian::new([9; 32]).get_council_inbox_pk();
        let misdirected = seal_delivery(
            &council_keys().0,
            &state.network_id,
            DeliveryPurpose::TxIo,
            1,
            &other_inbox,
            &PURPOSE_KEY,
        )
        .unwrap();
        assert_rejected(&state.deliver(&misdirected), RejectCode::WrongRecipient);

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
        let state = state_with_root_key(dir.path());
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
    fn restart_reloads_persisted_deliveries() {
        let dir = tempfile::tempdir().unwrap();
        let keys: Vec<[u8; 32]> = (1..=3u8).map(|e| [e; 32]).collect();
        {
            let state = state_with_root_key(dir.path());
            for (i, key) in keys.iter().enumerate() {
                assert_delivered(
                    &state.deliver(&seal(DeliveryPurpose::TxIo, (i + 1) as u64, *key)),
                    (i + 1) as u64,
                );
            }
        }
        // "Restart": a fresh state over the same directories.
        let state = state_with_root_key(dir.path());
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
            let state = state_with_root_key(dir.path());
            assert_delivered(&state.deliver(&seal(DeliveryPurpose::TxIo, 1, [1; 32])), 1);
            assert_delivered(&state.deliver(&envelope2), 2);
            assert_delivered(&state.deliver(&seal(DeliveryPurpose::TxIo, 3, [3; 32])), 3);
        }
        let epoch2_path = dir.path().join("deliveries/tx-io/2.cbor");
        fs::write(&epoch2_path, b"corrupted").unwrap();

        // Restart: the scan stops at the last good epoch before the damage.
        let state = state_with_root_key(dir.path());
        assert_eq!(state.status().tx_io_epoch, 1);
        assert_eq!(epoch_key(&state, DeliveryPurpose::TxIo, 1), Some([1; 32]));
        assert!(epoch_key(&state, DeliveryPurpose::TxIo, 2).is_none());

        // Redelivering the original envelope heals epoch 2 (rename-over)...
        assert_delivered(&state.deliver(&envelope2), 2);
        assert_eq!(epoch_key(&state, DeliveryPurpose::TxIo, 2), Some([2; 32]));

        // ...and epoch 3's file was never touched, so another restart
        // recovers the full sequence.
        let state = state_with_root_key(dir.path());
        assert_eq!(state.status().tx_io_epoch, 3);
        assert_eq!(epoch_key(&state, DeliveryPurpose::TxIo, 3), Some([3; 32]));
    }

    #[test]
    fn everything_waits_for_the_root_key() {
        let dir = tempfile::tempdir().unwrap();
        let state = awaiting_state(dir.path());
        assert_rejected(
            &state.deliver(&seal(DeliveryPurpose::TxIo, 1, PURPOSE_KEY)),
            RejectCode::RootKeyAbsent,
        );
        assert!(matches!(
            state.with_epoch_key(DeliveryPurpose::TxIo, 1, |_| ()),
            EpochKeyLookup::RootKeyAbsent
        ));
        let status = state.status();
        assert!(!status.accepting_deliveries);
        assert!(status.inbox_pk.is_none());
        assert_eq!(status.tx_io_epoch, 0);
    }

    #[test]
    fn unmountable_delivery_dir_defers_deliveries_but_answers_status() {
        let dir = tempfile::tempdir().unwrap();
        // A delivery dir under a *file* models /persistent not being mounted:
        // create_dir_all fails with ENOTDIR/ENOENT.
        let blocker = dir.path().join("not-a-dir");
        fs::write(&blocker, b"").unwrap();
        let base = CustodianState::new_with_root_key(
            Custodian::new(ROOT_KEY),
            dir.path().join("luks-keys"),
        )
        .unwrap();
        let state = CentralizedCustodianState::new(
            base,
            blocker.join("deliveries"),
            council_keys().1,
            crate::test_support::network_id(),
        );
        assert_rejected(
            &state.deliver(&seal(DeliveryPurpose::TxIo, 1, PURPOSE_KEY)),
            RejectCode::PersistenceUnavailable,
        );
        assert!(matches!(
            state.with_epoch_key(DeliveryPurpose::TxIo, 1, |_| ()),
            EpochKeyLookup::Unavailable
        ));
        let status = state.status();
        assert!(!status.accepting_deliveries);
        // The inbox key is derivable — only persistence blocks acceptance.
        assert!(status.inbox_pk.is_some());
    }
}
