//! Root-key lifecycle for the standalone custodian service.
//!
//! A genesis node starts with a freshly generated root key present. A joining
//! node binds the socket before it holds a root key and acquires it *through*
//! the socket: it starts awaiting, retains at most one requester-side
//! bootstrap attempt, and installs the root key from a verified, wrapped
//! bootstrap response. The requester's ephemeral ECDH secret never leaves
//! this process — the network-facing attestation service drives the evidence
//! exchange and sees only the public half.
//!
//! Both ways a root key becomes present — genesis construction and a verified
//! install — write the LUKS keyfile before the key is observable, so a
//! present root key always implies the handoff to `setup-persistent-luks`
//! has happened.
//!
//! The two ways also differ in one respect that outlives them: only the
//! custodian that minted the root key may release it to a peer admitted on
//! the founding policy, the chain's block-0 policy ([`FoundingPolicy`]). That
//! state is held here, next to the key, so the only way to reset it is to lose
//! the key.

use anyhow::{Context as _, Result, anyhow};
use rand::{TryRngCore as _, rngs::OsRng};
use secp256k1::PublicKey;
use seismic_custodian::{Custodian, EphemeralKeypair, unwrap_root_key};
use seismic_custodian_ipc::AdmittedOn;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};
use tracing::info;

/// The host's one custodian slot, shared by every connection thread.
pub struct CustodianState {
    inner: Mutex<RootKeyState>,
    /// Drop-zone for the LUKS keyfile, written whenever the root key becomes
    /// present.
    luks_keyfile: PathBuf,
}

// Variant names mirror the wire vocabulary (`RootKeyAlreadyPresent`,
// `RootKeyAbsent` in custodian-ipc).
enum RootKeyState {
    /// No root key yet (a joining node): only the bootstrap methods act.
    Absent { attempt: Option<PendingAttempt> },
    /// Root key held: derivations and wraps are served.
    Present {
        custodian: Custodian,
        founding_policy: FoundingPolicy,
    },
}

/// Whether this custodian wraps the root key for a peer admitted on the
/// founding policy — the founding accepted set, read at block 0 — rather than
/// on a fresh view of the live policy.
///
/// A chain view at block 0 is host-supplied and indistinguishable from a
/// withheld chain, so the host must not be able to bring the founding policy
/// back. Only the custodian that minted the root key starts out honoring it,
/// and it retires it once — when the chain is seen past genesis — for the rest
/// of that key's lifetime. Undoing that means restarting this process, which
/// loses the key; the node then rejoins with an installed key, which never
/// honors the founding policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FoundingPolicy {
    Honored,
    Retired,
}

/// Outcome of [`CustodianState::with_custodian_for_wrap`].
pub enum WrapGate<T> {
    Allowed(T),
    RootKeyAbsent,
    /// A founding-policy wrap, refused because the founding policy is
    /// retired.
    FoundingPolicyRetired,
}

/// One requester-side bootstrap attempt: the ephemeral secret retained for
/// exactly one exchange, addressed by an opaque id.
struct PendingAttempt {
    id: [u8; 32],
    eph: EphemeralKeypair,
}

/// Outcome of [`CustodianState::create_bootstrap_attempt`].
pub enum CreateAttemptOutcome {
    Created {
        attempt_id: [u8; 32],
        requester_eph_pk: [u8; 33],
    },
    RootKeyAlreadyPresent,
}

/// Outcome of [`CustodianState::install_root_key`].
pub enum InstallOutcome {
    Installed,
    RootKeyAlreadyPresent,
    /// No retained attempt matches the id: none was created, a newer attempt
    /// replaced it, or a previous install consumed it.
    UnknownAttempt,
    /// The wrapped key failed to open (bad point or AEAD mismatch). The
    /// matching attempt is consumed: a retry must start a fresh exchange, so
    /// a failed one leaks nothing reusable.
    InstallFailed(anyhow::Error),
    /// The root key was recovered but the LUKS keyfile write failed, so
    /// nothing was installed. Without the handoff the node cannot finish this
    /// boot; the host treats this as fatal.
    LuksKeyfileWriteFailed(anyhow::Error),
}

impl CustodianState {
    pub fn new_awaiting_root_key(luks_keyfile: PathBuf) -> Self {
        Self {
            inner: Mutex::new(RootKeyState::Absent { attempt: None }),
            luks_keyfile,
        }
    }

    /// A custodian holding the root key it just minted, so it starts out
    /// honoring the founding policy.
    ///
    /// Errors if the LUKS keyfile write fails: a root key is never present
    /// without the handoff done.
    pub fn new_with_root_key(custodian: Custodian, luks_keyfile: PathBuf) -> Result<Self> {
        write_luks_keyfile(&custodian, &luks_keyfile)?;
        Ok(Self {
            inner: Mutex::new(RootKeyState::Present {
                custodian,
                founding_policy: FoundingPolicy::Honored,
            }),
            luks_keyfile,
        })
    }

    /// Run `f` against the custodian, or `None` while no root key is present
    /// (callers answer `RootKeyAbsent`).
    pub fn with_custodian<T>(&self, f: impl FnOnce(&Custodian) -> T) -> Option<T> {
        match &*self.lock() {
            RootKeyState::Present { custodian, .. } => Some(f(custodian)),
            RootKeyState::Absent { .. } => None,
        }
    }

    /// Run the wrap `f` against the custodian, unless the peer was admitted on
    /// the founding policy and it is retired. The check
    /// and the wrap share one lock, so a retire cannot land between them.
    pub fn with_custodian_for_wrap<T>(
        &self,
        admitted_on: AdmittedOn,
        f: impl FnOnce(&Custodian) -> T,
    ) -> WrapGate<T> {
        match &*self.lock() {
            RootKeyState::Absent { .. } => WrapGate::RootKeyAbsent,
            RootKeyState::Present {
                founding_policy: FoundingPolicy::Retired,
                ..
            } if admitted_on == AdmittedOn::FoundingPolicy => WrapGate::FoundingPolicyRetired,
            RootKeyState::Present { custodian, .. } => WrapGate::Allowed(f(custodian)),
        }
    }

    /// Retire the founding policy, one way. `None` while no root key is
    /// present: there is no founding policy to retire without a key.
    pub fn retire_founding_policy(&self) -> Option<()> {
        match &mut *self.lock() {
            RootKeyState::Absent { .. } => None,
            RootKeyState::Present {
                founding_policy, ..
            } => {
                if *founding_policy == FoundingPolicy::Honored {
                    info!("retired the founding policy for this root key's lifetime");
                    *founding_policy = FoundingPolicy::Retired;
                }
                Some(())
            }
        }
    }

    /// Start a requester-side bootstrap attempt, replacing (and thereby
    /// invalidating) any previous one: one live exchange at a time, with a
    /// fresh ephemeral key per exchange.
    pub fn create_bootstrap_attempt(&self) -> CreateAttemptOutcome {
        match &mut *self.lock() {
            RootKeyState::Present { .. } => CreateAttemptOutcome::RootKeyAlreadyPresent,
            RootKeyState::Absent { attempt } => {
                let mut id = [0u8; 32];
                OsRng
                    .try_fill_bytes(&mut id)
                    .expect("OS RNG must produce an attempt id");
                let eph = EphemeralKeypair::generate();
                let requester_eph_pk = eph.pk_compressed();
                *attempt = Some(PendingAttempt { id, eph });
                CreateAttemptOutcome::Created {
                    attempt_id: id,
                    requester_eph_pk,
                }
            }
        }
    }

    /// Open a verified, wrapped bootstrap response with the retained attempt's
    /// ephemeral secret and install the recovered root key, writing the LUKS
    /// keyfile as part of the transition. An installed key never honors the
    /// founding policy: only the minter admits on it.
    ///
    /// The caller asserts, via its ACL grant, that the responder's evidence
    /// over this exact response transcript has been verified — mirroring
    /// `VerifiedPeerAuthorization` on the wrap side, the binding is opaque
    /// bytes here and the AEAD tag is the only local check.
    pub fn install_root_key(
        &self,
        attempt_id: [u8; 32],
        root_key_request_binding: [u8; 32],
        responder_eph_pk: [u8; 33],
        wrapped_root_key: &[u8],
    ) -> InstallOutcome {
        let mut state = self.lock();
        let attempt = match &mut *state {
            RootKeyState::Present { .. } => return InstallOutcome::RootKeyAlreadyPresent,
            // take_if: consume the attempt only on an id match — a stale id
            // must not invalidate a newer live attempt.
            RootKeyState::Absent { attempt } => {
                match attempt.take_if(|pending| pending.id == attempt_id) {
                    Some(pending) => pending,
                    None => return InstallOutcome::UnknownAttempt,
                }
            }
        };

        let responder_pk = match PublicKey::from_slice(&responder_eph_pk) {
            Ok(pk) => pk,
            Err(e) => {
                return InstallOutcome::InstallFailed(anyhow!(
                    "responder_eph_pk is not a valid compressed secp256k1 point: {e}"
                ));
            }
        };
        match unwrap_root_key(
            &attempt.eph.sk,
            &responder_pk,
            wrapped_root_key,
            &root_key_request_binding,
        ) {
            Ok(root_key) => {
                let custodian = Custodian::new(root_key);
                // The handoff precedes the transition: a present root key
                // always implies the LUKS keyfile has been written.
                if let Err(e) = write_luks_keyfile(&custodian, &self.luks_keyfile) {
                    return InstallOutcome::LuksKeyfileWriteFailed(e);
                }
                *state = RootKeyState::Present {
                    custodian,
                    founding_policy: FoundingPolicy::Retired,
                };
                InstallOutcome::Installed
            }
            Err(e) => InstallOutcome::InstallFailed(e),
        }
    }

    /// A panicking connection thread must not wedge every later request, so
    /// recover from poisoning; every transition assigns a whole variant, so
    /// no partially-updated state can be observed.
    fn lock(&self) -> MutexGuard<'_, RootKeyState> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Hand the LUKS keys off to `setup-persistent-luks` (seismic-images), which
/// polls for the file and shreds it after use.
fn write_luks_keyfile(custodian: &Custodian, path: &Path) -> Result<()> {
    custodian
        .write_luks_keyfile(path)
        .with_context(|| format!("writing LUKS keyfile {}", path.display()))?;
    info!(path = %path.display(), "wrote LUKS keyfile for setup-persistent-luks");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use seismic_custodian::VerifiedPeerAuthorization;
    use std::os::unix::fs::PermissionsExt as _;

    const ROOT_KEY: [u8; 32] = [7u8; 32];
    const BINDING: [u8; 32] = [0x33; 32];

    fn tmp_luks() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("luks-keys");
        (dir, path)
    }

    fn awaiting(luks_keyfile: &Path) -> CustodianState {
        CustodianState::new_awaiting_root_key(luks_keyfile.to_path_buf())
    }

    fn with_root_key(luks_keyfile: &Path) -> CustodianState {
        CustodianState::new_with_root_key(Custodian::new(ROOT_KEY), luks_keyfile.to_path_buf())
            .expect("write LUKS keyfile")
    }

    /// Responder side of the handshake, straight against the library.
    fn wrap_for(responder: &Custodian, requester_eph_pk: [u8; 33]) -> ([u8; 33], Vec<u8>) {
        let pk = PublicKey::from_slice(&requester_eph_pk).expect("valid requester point");
        let wrapped = responder
            .wrap_root_key_for_peer(
                &VerifiedPeerAuthorization {
                    root_key_request_binding: BINDING,
                },
                &pk,
            )
            .expect("wrap");
        (wrapped.responder_eph_pk.serialize(), wrapped.wrapped)
    }

    fn created(state: &CustodianState) -> ([u8; 32], [u8; 33]) {
        let CreateAttemptOutcome::Created {
            attempt_id,
            requester_eph_pk,
        } = state.create_bootstrap_attempt()
        else {
            panic!("expected a created attempt");
        };
        (attempt_id, requester_eph_pk)
    }

    /// The deployment contract with setup-persistent-luks: 64 raw bytes
    /// (`storage_key || header_mac_key`), owner-read-only.
    fn assert_luks_keyfile(path: &Path) {
        let metadata = std::fs::metadata(path).expect("LUKS keyfile written");
        assert_eq!(metadata.len(), 64);
        assert_eq!(metadata.permissions().mode() & 0o777, 0o400);
    }

    #[test]
    fn present_root_key_reports_already_present() {
        let (_dir, luks) = tmp_luks();
        let state = with_root_key(&luks);
        assert!(state.with_custodian(|_| ()).is_some());
        assert!(matches!(
            state.create_bootstrap_attempt(),
            CreateAttemptOutcome::RootKeyAlreadyPresent
        ));
        assert!(matches!(
            state.install_root_key([0; 32], BINDING, [0; 33], &[]),
            InstallOutcome::RootKeyAlreadyPresent
        ));
    }

    #[test]
    fn awaiting_state_withholds_the_custodian_and_refuses_blind_installs() {
        let (_dir, luks) = tmp_luks();
        let state = awaiting(&luks);
        assert!(state.with_custodian(|_| ()).is_none());
        assert!(matches!(
            state.install_root_key([0; 32], BINDING, [0; 33], &[]),
            InstallOutcome::UnknownAttempt
        ));
    }

    #[test]
    fn root_key_construction_writes_the_luks_keyfile() {
        let (_dir, luks) = tmp_luks();
        let _state = with_root_key(&luks);
        assert_luks_keyfile(&luks);
    }

    #[test]
    fn construction_fails_when_the_luks_keyfile_is_unwritable() {
        let (dir, _) = tmp_luks();
        let unwritable = dir.path().join("missing-dir").join("luks-keys");
        assert!(CustodianState::new_with_root_key(Custodian::new(ROOT_KEY), unwritable).is_err());
    }

    #[test]
    fn bootstrap_roundtrip_installs_the_wrapped_root_key() {
        let (_dir, luks) = tmp_luks();
        let responder = Custodian::new(ROOT_KEY);
        let state = awaiting(&luks);

        let (attempt_id, requester_eph_pk) = created(&state);
        let (responder_eph_pk, wrapped) = wrap_for(&responder, requester_eph_pk);
        assert!(matches!(
            state.install_root_key(attempt_id, BINDING, responder_eph_pk, &wrapped),
            InstallOutcome::Installed
        ));

        // Both custodians now derive identical purpose keys, and the install
        // wrote the LUKS handoff.
        let installed_sk = state
            .with_custodian(|c| c.get_tx_io_sk(0))
            .expect("root key present");
        assert_eq!(installed_sk, responder.get_tx_io_sk(0));
        assert_luks_keyfile(&luks);
    }

    #[test]
    fn failed_luks_write_leaves_the_root_key_absent() {
        let (dir, _) = tmp_luks();
        let unwritable = dir.path().join("missing-dir").join("luks-keys");
        let responder = Custodian::new(ROOT_KEY);
        let state = awaiting(&unwritable);

        let (attempt_id, requester_eph_pk) = created(&state);
        let (responder_eph_pk, wrapped) = wrap_for(&responder, requester_eph_pk);
        assert!(matches!(
            state.install_root_key(attempt_id, BINDING, responder_eph_pk, &wrapped),
            InstallOutcome::LuksKeyfileWriteFailed(_)
        ));
        assert!(state.with_custodian(|_| ()).is_none());
    }

    #[test]
    fn stale_attempt_id_is_refused_without_consuming_the_live_attempt() {
        let (_dir, luks) = tmp_luks();
        let responder = Custodian::new(ROOT_KEY);
        let state = awaiting(&luks);

        let (stale_id, _) = created(&state);
        let (live_id, requester_eph_pk) = created(&state);
        assert_ne!(stale_id, live_id);

        let (responder_eph_pk, wrapped) = wrap_for(&responder, requester_eph_pk);
        assert!(matches!(
            state.install_root_key(stale_id, BINDING, responder_eph_pk, &wrapped),
            InstallOutcome::UnknownAttempt
        ));
        assert!(matches!(
            state.install_root_key(live_id, BINDING, responder_eph_pk, &wrapped),
            InstallOutcome::Installed
        ));
    }

    #[test]
    fn failed_install_consumes_the_attempt() {
        let (_dir, luks) = tmp_luks();
        let responder = Custodian::new(ROOT_KEY);
        let state = awaiting(&luks);

        let (attempt_id, requester_eph_pk) = created(&state);
        let (responder_eph_pk, wrapped) = wrap_for(&responder, requester_eph_pk);

        // Wrapped under BINDING, opened under a foreign binding: AEAD fails.
        assert!(matches!(
            state.install_root_key(attempt_id, [0xFF; 32], responder_eph_pk, &wrapped),
            InstallOutcome::InstallFailed(_)
        ));
        // The attempt is gone: even the correct binding can't reuse it.
        assert!(matches!(
            state.install_root_key(attempt_id, BINDING, responder_eph_pk, &wrapped),
            InstallOutcome::UnknownAttempt
        ));
        assert!(state.with_custodian(|_| ()).is_none());
    }

    /// Whether a founding-policy wrap would be served right now.
    fn wraps_on_founding_policy(state: &CustodianState) -> bool {
        match state.with_custodian_for_wrap(AdmittedOn::FoundingPolicy, |_| ()) {
            WrapGate::Allowed(()) => true,
            WrapGate::FoundingPolicyRetired => false,
            WrapGate::RootKeyAbsent => panic!("expected a present root key"),
        }
    }

    fn wraps_on_live_policy(state: &CustodianState) -> bool {
        matches!(
            state.with_custodian_for_wrap(AdmittedOn::LivePolicy, |_| ()),
            WrapGate::Allowed(())
        )
    }

    #[test]
    fn the_minting_custodian_honors_the_founding_policy_until_retired() {
        let (_dir, luks) = tmp_luks();
        let state = with_root_key(&luks);
        assert!(wraps_on_founding_policy(&state));

        assert_eq!(state.retire_founding_policy(), Some(()));
        assert!(!wraps_on_founding_policy(&state));
        assert!(wraps_on_live_policy(&state));

        // One way: retiring again changes nothing, and nothing brings it back.
        assert_eq!(state.retire_founding_policy(), Some(()));
        assert!(!wraps_on_founding_policy(&state));
    }

    #[test]
    fn an_installed_root_key_never_honors_the_founding_policy() {
        let (_dir, luks) = tmp_luks();
        let responder = Custodian::new(ROOT_KEY);
        let state = awaiting(&luks);
        let (attempt_id, requester_eph_pk) = created(&state);
        let (responder_eph_pk, wrapped) = wrap_for(&responder, requester_eph_pk);
        assert!(matches!(
            state.install_root_key(attempt_id, BINDING, responder_eph_pk, &wrapped),
            InstallOutcome::Installed
        ));

        assert!(!wraps_on_founding_policy(&state));
        assert!(wraps_on_live_policy(&state));
    }

    #[test]
    fn no_root_key_means_no_founding_policy_to_retire() {
        let (_dir, luks) = tmp_luks();
        let state = awaiting(&luks);
        assert_eq!(state.retire_founding_policy(), None);
        assert!(matches!(
            state.with_custodian_for_wrap(AdmittedOn::FoundingPolicy, |_| ()),
            WrapGate::RootKeyAbsent
        ));
    }

    #[test]
    fn invalid_responder_point_fails_the_install() {
        let (_dir, luks) = tmp_luks();
        let state = awaiting(&luks);
        let (attempt_id, _) = created(&state);
        assert!(matches!(
            state.install_root_key(attempt_id, BINDING, [0; 33], &[0; 60]),
            InstallOutcome::InstallFailed(_)
        ));
    }
}
