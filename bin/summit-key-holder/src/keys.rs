//! Summit keypair generation and keystore I/O.
//!
//! The keystore written here is read back by summit's `KeyPaths`
//! (`types/src/key_paths.rs`), so the wire format is summit's, byte for
//! byte: `node_key.pem` and `consensus_key.pem`, each the bare lowercase
//! hex of the commonware-codec key encoding (64 chars — both private keys
//! are 32-byte scalars), no `0x`, no trailing newline, file mode 0600 in a
//! 0700 directory. Summit's reader is lenient (`from_hex_formatted`), but
//! its own writer emits exactly this, and the golden-vector test below pins
//! us to a keystore summit's `keys generate` produced.
//!
//! Private keys never leave this module as raw bytes: [`HeldKeys`] hands
//! out only public material, and both commonware key types zeroize on drop.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use commonware_codec::Encode as _;
use commonware_cryptography::Signer as _;
use commonware_cryptography::{bls12381, ed25519};
use commonware_math::algebra::Random as _;

use crate::error::HolderError;

/// Summit's node-identity key filename (`KeyPaths::node_key_path_str`).
pub const NODE_KEY_FILE: &str = "node_key.pem";
/// Summit's consensus key filename (`KeyPaths::consensus_key_path_str`).
pub const CONSENSUS_KEY_FILE: &str = "consensus_key.pem";

/// The summit keypairs, held in RAM between boot and persist.
///
/// Deliberately not `Clone`: exactly one copy per process, dropped (and
/// zeroized — both commonware private key types wrap their scalar in a
/// zeroizing `Secret`) at persist or with the process.
pub struct HeldKeys {
    node: ed25519::PrivateKey,
    consensus: bls12381::PrivateKey,
}

impl HeldKeys {
    /// Generate a fresh keypair set from the OS RNG.
    pub fn generate() -> Self {
        Self {
            node: ed25519::PrivateKey::random(&mut rand_08::rngs::OsRng),
            consensus: bls12381::PrivateKey::random(&mut rand_08::rngs::OsRng),
        }
    }

    pub fn public_keys(&self) -> PublicKeys {
        PublicKeys::derive(&self.node, &self.consensus)
    }
}

/// Public halves of a summit keypair set, as the fixed-size raw bytes the
/// founding binding hashes. Hex rendering matches summit's (`Display` on
/// commonware public keys): bare lowercase, no `0x`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKeys {
    pub node: [u8; 32],
    pub consensus: [u8; 48],
}

impl PublicKeys {
    fn derive(node: &ed25519::PrivateKey, consensus: &bls12381::PrivateKey) -> Self {
        let node = node
            .public_key()
            .encode()
            .as_ref()
            .try_into()
            .expect("ed25519 public keys encode to 32 bytes");
        let consensus = consensus
            .public_key()
            .encode()
            .as_ref()
            .try_into()
            .expect("BLS12-381 MinPk public keys encode to 48 bytes");
        Self { node, consensus }
    }

    pub fn node_hex(&self) -> String {
        commonware_utils::hex(&self.node)
    }

    pub fn consensus_hex(&self) -> String {
        commonware_utils::hex(&self.consensus)
    }
}

/// What exists at a keystore path. `Partial` is an error to act on —
/// writing would clobber half a keystore, confirming would vouch for one —
/// unless [`partial_matches_held`] proves it is this boot's own interrupted
/// persist, which finishing converges.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeystoreStatus {
    Absent,
    Partial,
    Present,
}

/// Report which of the two key files exist under `dir`.
///
/// A missing directory is `Absent`, not an error: pre-LUKS the keystore's
/// mount point does not exist yet, and the uniform serving rule ("keystore
/// if present, else RAM") relies on that reading.
pub fn keystore_status(dir: &Path) -> KeystoreStatus {
    let node = dir.join(NODE_KEY_FILE).is_file();
    let consensus = dir.join(CONSENSUS_KEY_FILE).is_file();
    match (node, consensus) {
        (true, true) => KeystoreStatus::Present,
        (false, false) => KeystoreStatus::Absent,
        _ => KeystoreStatus::Partial,
    }
}

/// Whether every key file that *does* exist under `dir` holds exactly the
/// keys in `keys`.
///
/// This is what makes a `Partial` keystore safe to finish: each file lands
/// atomically (temp + rename), so a half-written keystore's one file is a
/// complete key — if it decodes to the held RAM key, the partial state is
/// this boot's own interrupted persist and rewriting converges on the
/// keystore that persist was building. Foreign or undecodable content is
/// `false`: overwriting it would silently mint keys the manifest never
/// pinned.
pub fn partial_matches_held(dir: &Path, keys: &HeldKeys) -> bool {
    let file_matches = |file: &str, held_encoding: &[u8]| {
        let path = dir.join(file);
        !path.is_file()
            || fs::read_to_string(&path)
                .ok()
                .and_then(|encoded| commonware_utils::from_hex_formatted(&encoded))
                .is_some_and(|raw| raw.as_slice() == held_encoding)
    };
    file_matches(NODE_KEY_FILE, keys.node.encode().as_ref())
        && file_matches(CONSENSUS_KEY_FILE, keys.consensus.encode().as_ref())
}

/// Write `keys` into `dir` in summit's keystore format.
///
/// The directory is created 0700 like summit's `create_keystore_dir`; each
/// file lands via a same-directory temp file (`create_new`, mode 0600,
/// `sync_all`) renamed into place, so a reader polling for the exact path
/// never observes a partially-written key — the same discipline as the
/// custodian's LUKS keyfile.
pub fn write_keystore(dir: &Path, keys: &HeldKeys) -> Result<(), HolderError> {
    create_keystore_dir(dir).map_err(|e| {
        HolderError::Keystore(format!("creating keystore dir {}: {e}", dir.display()))
    })?;
    write_key_file(
        &dir.join(NODE_KEY_FILE),
        &commonware_utils::hex(&keys.node.encode()),
    )?;
    write_key_file(
        &dir.join(CONSENSUS_KEY_FILE),
        &commonware_utils::hex(&keys.consensus.encode()),
    )?;
    Ok(())
}

/// Read both key files from `dir` and derive their public halves.
///
/// Decoding the privates (rather than stat-ing the files) is the point:
/// `Confirmed` from the persist op and every post-persist `/v1/keys`
/// response vouch for a keystore summit will actually be able to load.
pub fn read_keystore_public_keys(dir: &Path) -> Result<PublicKeys, HolderError> {
    let node: ed25519::PrivateKey = read_key_file(&dir.join(NODE_KEY_FILE))?;
    let consensus: bls12381::PrivateKey = read_key_file(&dir.join(CONSENSUS_KEY_FILE))?;
    Ok(PublicKeys::derive(&node, &consensus))
}

fn read_key_file<K: commonware_codec::DecodeExt<()>>(path: &Path) -> Result<K, HolderError> {
    let encoded = fs::read_to_string(path)
        .map_err(|e| HolderError::Keystore(format!("reading {}: {e}", path.display())))?;
    let raw = commonware_utils::from_hex_formatted(&encoded)
        .ok_or_else(|| HolderError::Keystore(format!("{} is not hex", path.display())))?;
    K::decode(raw.as_ref())
        .map_err(|e| HolderError::Keystore(format!("decoding {}: {e}", path.display())))
}

/// Create the keystore directory 0700, exactly like summit's
/// `create_keystore_dir` — private keys land here, so a permissive umask
/// must not leak into the directory mode.
fn create_keystore_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(dir)
    }
}

fn write_key_file(path: &Path, contents: &str) -> Result<(), HolderError> {
    let tmp = tmp_path(path);
    let write = || -> std::io::Result<()> {
        // A crash between temp-create and rename strands a temp file on the
        // persistent disk, and `create_new` would then fail every later
        // persist; clear it first. `create_new` still closes the race window
        // between two live writers.
        match fs::remove_file(&tmp) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let mut open = fs::OpenOptions::new();
        open.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            open.mode(0o600);
        }
        let mut file = open.open(&tmp)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        fs::rename(&tmp, path)
    };
    write().map_err(|e| {
        // Best-effort cleanup so a failed write doesn't strand a temp file
        // that fails the next attempt's `create_new`.
        let _ = fs::remove_file(&tmp);
        HolderError::Keystore(format!("writing {}: {e}", path.display()))
    })
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .expect("key paths have filenames")
        .to_owned();
    name.push(".tmp");
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::DecodeExt as _;

    /// Golden vectors: a keystore emitted by summit's `keys generate`
    /// (summit `testnet/node0`, committed at
    /// <https://github.com/SeismicSystems/summit/tree/main/testnet/node0>),
    /// whose public keys are independently pinned as the first validator of
    /// summit's `example_genesis.toml`.
    const SUMMIT_NODE_KEY_FILE: &str =
        "19887e80c3ebb397ef2167b52beb89eab9208699f918dfb311c9a44cb52f8b25";
    const SUMMIT_CONSENSUS_KEY_FILE: &str =
        "0097b3521bf678203a7fb449b3d5e4870ce56cac94c837b6a116a78f902a891f";
    const SUMMIT_NODE_PUBKEY: &str =
        "1be3cb06d7cc347602421fb73838534e4b54934e28959de98906d120d0799ef2";
    const SUMMIT_CONSENSUS_PUBKEY: &str = "a6f61154ae7be4fd38cd43cf69adfd4896c57473cacb389702bb83f8adf923eecf4854c745e064c0a2db79db5674332b";

    fn summit_keystore(dir: &Path) {
        fs::write(dir.join(NODE_KEY_FILE), SUMMIT_NODE_KEY_FILE).unwrap();
        fs::write(dir.join(CONSENSUS_KEY_FILE), SUMMIT_CONSENSUS_KEY_FILE).unwrap();
    }

    #[test]
    fn golden_vector_reads_summit_keystore() {
        let dir = tempfile::tempdir().unwrap();
        summit_keystore(dir.path());
        let keys = read_keystore_public_keys(dir.path()).unwrap();
        assert_eq!(keys.node_hex(), SUMMIT_NODE_PUBKEY);
        assert_eq!(keys.consensus_hex(), SUMMIT_CONSENSUS_PUBKEY);
    }

    #[test]
    fn golden_vector_write_matches_summit_bytes() {
        // Decode the summit-emitted privates, write them through our writer,
        // and require the exact file bytes back: this is the byte-parity pin
        // on the wire format (bare lowercase hex, no 0x, no newline).
        let node = ed25519::PrivateKey::decode(
            commonware_utils::from_hex(SUMMIT_NODE_KEY_FILE)
                .unwrap()
                .as_ref(),
        )
        .unwrap();
        let consensus = bls12381::PrivateKey::decode(
            commonware_utils::from_hex(SUMMIT_CONSENSUS_KEY_FILE)
                .unwrap()
                .as_ref(),
        )
        .unwrap();
        let keys = HeldKeys { node, consensus };

        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("keys");
        write_keystore(&store, &keys).unwrap();

        let node_bytes = fs::read(store.join(NODE_KEY_FILE)).unwrap();
        let consensus_bytes = fs::read(store.join(CONSENSUS_KEY_FILE)).unwrap();
        assert_eq!(node_bytes, SUMMIT_NODE_KEY_FILE.as_bytes());
        assert_eq!(consensus_bytes, SUMMIT_CONSENSUS_KEY_FILE.as_bytes());

        let read_back = read_keystore_public_keys(&store).unwrap();
        assert_eq!(read_back.node_hex(), SUMMIT_NODE_PUBKEY);
        assert_eq!(read_back.consensus_hex(), SUMMIT_CONSENSUS_PUBKEY);
    }

    #[cfg(unix)]
    #[test]
    fn keystore_permissions_match_summit() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("keys");
        write_keystore(&store, &HeldKeys::generate()).unwrap();

        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode(&store), 0o700);
        assert_eq!(mode(&store.join(NODE_KEY_FILE)), 0o600);
        assert_eq!(mode(&store.join(CONSENSUS_KEY_FILE)), 0o600);
    }

    #[test]
    fn generate_write_read_round_trips() {
        let keys = HeldKeys::generate();
        let expected = keys.public_keys();
        assert_eq!(expected.node_hex().len(), 64);
        assert_eq!(expected.consensus_hex().len(), 96);

        let dir = tempfile::tempdir().unwrap();
        write_keystore(dir.path(), &keys).unwrap();
        assert_eq!(read_keystore_public_keys(dir.path()).unwrap(), expected);
    }

    #[test]
    fn status_distinguishes_absent_partial_present() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("nonexistent");
        assert_eq!(keystore_status(&store), KeystoreStatus::Absent);

        assert_eq!(keystore_status(dir.path()), KeystoreStatus::Absent);
        fs::write(dir.path().join(NODE_KEY_FILE), SUMMIT_NODE_KEY_FILE).unwrap();
        assert_eq!(keystore_status(dir.path()), KeystoreStatus::Partial);
        fs::write(
            dir.path().join(CONSENSUS_KEY_FILE),
            SUMMIT_CONSENSUS_KEY_FILE,
        )
        .unwrap();
        assert_eq!(keystore_status(dir.path()), KeystoreStatus::Present);
    }

    #[test]
    fn partial_matches_held_distinguishes_own_write_from_foreign() {
        let keys = HeldKeys::generate();
        let dir = tempfile::tempdir().unwrap();

        // Our own interrupted write: one file, holding the held node key.
        write_keystore(dir.path(), &keys).unwrap();
        fs::remove_file(dir.path().join(CONSENSUS_KEY_FILE)).unwrap();
        assert!(partial_matches_held(dir.path(), &keys));

        // The same file holding someone else's key, or garbage: foreign.
        fs::write(dir.path().join(NODE_KEY_FILE), SUMMIT_NODE_KEY_FILE).unwrap();
        assert!(!partial_matches_held(dir.path(), &keys));
        fs::write(dir.path().join(NODE_KEY_FILE), "not hex").unwrap();
        assert!(!partial_matches_held(dir.path(), &keys));
    }

    #[test]
    fn stale_temp_file_does_not_block_a_later_write() {
        // A crash between temp-create and rename must not wedge every later
        // persist attempt: the writer clears its own stale temp file first.
        let keys = HeldKeys::generate();
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(format!("{NODE_KEY_FILE}.tmp")), "stale").unwrap();
        write_keystore(dir.path(), &keys).unwrap();
        assert_eq!(
            read_keystore_public_keys(dir.path()).unwrap(),
            keys.public_keys()
        );
    }
}
