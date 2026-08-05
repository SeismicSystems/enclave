//! The holder's key state machine.
//!
//! One rule decides what every surface serves: **keystore if present, else
//! RAM**. At boot the keystore's mount point does not even exist (LUKS has
//! not opened `/persistent`), so fresh RAM keys serve; after `persist`, the
//! keystore serves — for life, feeding the launch-time pubkey-continuity
//! assertion. The uniform rule also makes the per-boot rewind harmless: a
//! rebooted node regenerates RAM keys and serves them until `persist`
//! discards them in favor of the keystore it confirms.

use std::path::PathBuf;
use std::sync::Mutex;

use crate::error::HolderError;
use crate::keys::{
    HeldKeys, KeystoreStatus, PublicKeys, keystore_status, partial_matches_held,
    read_keystore_public_keys, write_keystore,
};

/// What a `persist` request did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PersistOutcome {
    /// First boot: the RAM keys were written into the keystore.
    Persisted(PublicKeys),
    /// Reboot: the keystore already existed and decoded cleanly; this
    /// boot's RAM keys were discarded.
    Confirmed(PublicKeys),
}

impl PersistOutcome {
    pub fn public_keys(&self) -> &PublicKeys {
        match self {
            PersistOutcome::Persisted(keys) | PersistOutcome::Confirmed(keys) => keys,
        }
    }
}

pub struct Holder {
    /// RAM keys, present from boot until `persist` drops them (dropping a
    /// commonware private key zeroizes it). The mutex also serializes
    /// concurrent `persist` requests.
    ram: Mutex<Option<HeldKeys>>,
    keystore_dir: PathBuf,
    manifest_path: PathBuf,
    /// Serializes evidence generation within this process: the vTPM quote
    /// path is exclusive-open on `/dev/tpm0` and takes seconds per call.
    /// (Cross-process serialization is by design: this service stops
    /// quoting once the manifest exists, before attestation-service — the
    /// TPM's owner from then on — starts.)
    pub quote_gate: tokio::sync::Mutex<()>,
}

impl Holder {
    /// Generate fresh RAM keys and stand up the state machine.
    pub fn new(keystore_dir: PathBuf, manifest_path: PathBuf) -> Self {
        Self::with_keys(HeldKeys::generate(), keystore_dir, manifest_path)
    }

    /// Stand up the state machine over known keys — tests plant these on
    /// disk to fabricate an "own interrupted write" partial keystore.
    pub(crate) fn with_keys(keys: HeldKeys, keystore_dir: PathBuf, manifest_path: PathBuf) -> Self {
        Self {
            ram: Mutex::new(Some(keys)),
            keystore_dir,
            manifest_path,
            quote_gate: tokio::sync::Mutex::new(()),
        }
    }

    /// The uniform serving rule: keystore if present, else RAM keys.
    pub fn public_keys(&self) -> Result<PublicKeys, HolderError> {
        match keystore_status(&self.keystore_dir) {
            KeystoreStatus::Present => read_keystore_public_keys(&self.keystore_dir),
            KeystoreStatus::Partial => Err(self.partial_keystore_error()),
            KeystoreStatus::Absent => self
                .ram
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
                .map(HeldKeys::public_keys)
                .ok_or(HolderError::NoKeys),
        }
    }

    /// Quotes are served only until the network manifest lands: from the
    /// config POST onward, attestation-service owns the TPM quote path.
    /// A per-request stat of the tmpfs path is the freshest possible check.
    pub fn quote_window_open(&self) -> bool {
        !self.manifest_path.exists()
    }

    /// The control socket's one operation: write the keystore if absent,
    /// confirm it if present, discard the RAM keys either way.
    ///
    /// Holding the RAM lock across the whole operation serializes
    /// concurrent `persist` requests, so exactly one writer ever runs.
    pub fn persist(&self) -> Result<PersistOutcome, HolderError> {
        let mut ram = self
            .ram
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match keystore_status(&self.keystore_dir) {
            KeystoreStatus::Present => {
                // Decode before vouching: `Confirmed` must mean summit can
                // load these files, not merely that they exist.
                let keys = read_keystore_public_keys(&self.keystore_dir)?;
                // This boot's RAM keys were never pinned; the launch
                // continuity assertion is what surfaces a mismatch between
                // the confirmed keystore and the manifest.
                *ram = None;
                Ok(PersistOutcome::Confirmed(keys))
            }
            KeystoreStatus::Partial => {
                // A partial keystore that provably holds this boot's own RAM
                // keys is an interrupted persist (each file lands atomically,
                // so the one that exists is a complete key): finishing the
                // write converges on the keystore that attempt was building.
                // Anything else — a prior boot's remnant, foreign content —
                // is refused: overwriting would silently mint keys the
                // manifest never pinned.
                let held = ram.as_ref().ok_or_else(|| self.partial_keystore_error())?;
                if !partial_matches_held(&self.keystore_dir, held) {
                    return Err(self.partial_keystore_error());
                }
                write_keystore(&self.keystore_dir, held)?;
                let keys = held.public_keys();
                *ram = None;
                Ok(PersistOutcome::Persisted(keys))
            }
            KeystoreStatus::Absent => {
                let held = ram.as_ref().ok_or(HolderError::NoKeys)?;
                write_keystore(&self.keystore_dir, held)?;
                let keys = held.public_keys();
                *ram = None;
                Ok(PersistOutcome::Persisted(keys))
            }
        }
    }

    fn partial_keystore_error(&self) -> HolderError {
        HolderError::Keystore(format!(
            "partial keystore at {}: exactly one of node_key.pem/consensus_key.pem exists; \
             refusing to write over or vouch for it",
            self.keystore_dir.display()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    fn holder(dir: &Path) -> Holder {
        Holder::new(dir.join("keys"), dir.join("network-manifest.json"))
    }

    #[test]
    fn serves_ram_keys_until_persist_then_keystore() {
        let dir = tempfile::tempdir().unwrap();
        let holder = holder(dir.path());

        let ram_keys = holder.public_keys().unwrap();
        let outcome = holder.persist().unwrap();
        assert_eq!(outcome, PersistOutcome::Persisted(ram_keys.clone()));

        // Post-persist the keystore serves, and it holds the same keys.
        assert_eq!(holder.public_keys().unwrap(), ram_keys);
    }

    #[test]
    fn persist_on_existing_keystore_confirms_and_discards_ram_keys() {
        let dir = tempfile::tempdir().unwrap();
        let first_boot = holder(dir.path());
        let pinned = match first_boot.persist().unwrap() {
            PersistOutcome::Persisted(keys) => keys,
            other => panic!("expected Persisted, got {other:?}"),
        };

        // A "reboot": a fresh holder with fresh RAM keys over the same dir.
        let rebooted = holder(dir.path());
        assert_eq!(
            rebooted.persist().unwrap(),
            PersistOutcome::Confirmed(pinned.clone())
        );
        // The fresh RAM keys are gone; the pinned keystore serves.
        assert_eq!(rebooted.public_keys().unwrap(), pinned);
    }

    #[test]
    fn keystore_wins_over_ram_keys_before_persist() {
        // Uniform rule: a rebooted node with an already-opened keystore
        // serves the pinned keys even before its persist confirms them.
        let dir = tempfile::tempdir().unwrap();
        let first_boot = holder(dir.path());
        let pinned = first_boot.persist().unwrap().public_keys().clone();

        let rebooted = holder(dir.path());
        assert_eq!(rebooted.public_keys().unwrap(), pinned);
    }

    #[test]
    fn persist_finishes_its_own_interrupted_write() {
        // Simulate a persist that crashed between the two file writes: one
        // complete key file holding this boot's own RAM key. The retry must
        // finish the keystore rather than wedge on Partial.
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("keys");
        let keys = HeldKeys::generate();
        write_keystore(&store, &keys).unwrap();
        fs::remove_file(store.join(crate::keys::CONSENSUS_KEY_FILE)).unwrap();

        let holder = Holder::with_keys(keys, store, dir.path().join("network-manifest.json"));
        // Serving still refuses the Partial state; only persist repairs it.
        assert!(matches!(
            holder.public_keys(),
            Err(HolderError::Keystore(_))
        ));

        let outcome = holder.persist().unwrap();
        let pinned = match outcome {
            PersistOutcome::Persisted(keys) => keys,
            other => panic!("expected Persisted, got {other:?}"),
        };
        assert_eq!(holder.public_keys().unwrap(), pinned);
    }

    #[test]
    fn persist_refuses_a_foreign_partial_keystore() {
        // A prior boot's remnant: a valid key file that is NOT this boot's
        // RAM key. Overwriting would mint unpinned keys — refuse loudly.
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("keys");
        write_keystore(&store, &HeldKeys::generate()).unwrap();
        fs::remove_file(store.join(crate::keys::CONSENSUS_KEY_FILE)).unwrap();

        let holder = Holder::new(store, dir.path().join("network-manifest.json"));
        let err = holder.persist().unwrap_err();
        assert!(matches!(err, HolderError::Keystore(_)));
    }

    #[test]
    fn partial_keystore_is_refused_everywhere() {
        let dir = tempfile::tempdir().unwrap();
        let holder = holder(dir.path());
        fs::create_dir_all(dir.path().join("keys")).unwrap();
        fs::write(dir.path().join("keys/node_key.pem"), "00").unwrap();

        assert!(matches!(
            holder.public_keys(),
            Err(HolderError::Keystore(_))
        ));
        assert!(matches!(holder.persist(), Err(HolderError::Keystore(_))));
    }

    #[test]
    fn persist_after_persist_confirms() {
        // summit.service restarts re-run persist-wait; the second persist
        // must confirm rather than fail on the discarded RAM keys.
        let dir = tempfile::tempdir().unwrap();
        let holder = holder(dir.path());
        let pinned = holder.persist().unwrap().public_keys().clone();
        assert_eq!(holder.persist().unwrap(), PersistOutcome::Confirmed(pinned));
    }

    #[test]
    fn quote_window_tracks_manifest_presence() {
        let dir = tempfile::tempdir().unwrap();
        let holder = holder(dir.path());
        assert!(holder.quote_window_open());
        fs::write(dir.path().join("network-manifest.json"), "{}").unwrap();
        assert!(!holder.quote_window_open());
    }
}
