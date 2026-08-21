use anyhow::Result;
use hkdf::Hkdf;
use rand::{TryRngCore as _, rngs::OsRng};
use sha2::Sha256;
use zeroize::ZeroizeOnDrop;

/// Salt used during HKDF key derivation for purpose-specific keys.
const PURPOSE_DERIVE_SALT: &[u8] = b"seismic-purpose-derive-salt";
/// Prefix used in domain separation when deriving purpose-specific keys.
const PREFIX: &str = "seismic-purpose";

/// Holder of the network root key; every other secret is derived from it on
/// demand. Deliberately not `Clone`: exactly one copy per process, zeroized
/// when the custodian drops.
#[derive(ZeroizeOnDrop)]
pub struct Custodian {
    pub(crate) root_key: [u8; 32],
}

/// Enum representing the intended usage ("purpose") of a derived key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum KeyPurpose {
    Snapshot,
    RngPrecompile,
    TxIo,
    /// LUKS volume unlock key.
    Storage,
    /// HMAC key for verifying the LUKS2 header against tampering:
    /// <https://blog.trailofbits.com/2025/10/30/vulnerabilities-in-luks2-disk-encryption-for-confidential-vms/>
    /// Used by setup-persistent-luks to MAC `segments + keyslots + digests`
    /// and store the result as a custom LUKS2 token; verified on every subsequent boot
    /// before `cryptsetup open`.
    LuksHeaderMac,
}

impl KeyPurpose {
    /// Returns the short string label for the purpose.
    fn label(&self) -> &'static str {
        match self {
            KeyPurpose::Snapshot => "snapshot",
            KeyPurpose::RngPrecompile => "rng-precompile",
            KeyPurpose::TxIo => "tx-io",
            KeyPurpose::Storage => "storage",
            KeyPurpose::LuksHeaderMac => "luks-header-mac",
        }
    }

    /// Returns the domain separator for this purpose, used in HKDF expansion.
    fn domain_separator(&self) -> Vec<u8> {
        format!("{PREFIX}-{}", self.label()).into_bytes()
    }
}

impl Custodian {
    /// Install an already-obtained root key (the joining-node path: the caller
    /// ran the attested bootstrap handshake and unwrapped the peer's response).
    pub fn new(root_key: [u8; 32]) -> Self {
        Self { root_key }
    }

    /// Generate a fresh root key from the OS CSPRNG (the genesis-node path).
    pub fn new_as_genesis() -> Result<Self> {
        let mut rng = OsRng;
        let mut rng_bytes = [0u8; 32];
        rng.try_fill_bytes(&mut rng_bytes)?;

        let km = Custodian::new(rng_bytes);
        Ok(km)
    }

    /// HKDF-expands the root key into `N` bytes for one purpose and epoch.
    /// Every purpose takes 32 bytes except `RngPrecompile`, whose precompile
    /// wants 64 bytes of IKM.
    ///
    /// Crate-internal, so every purpose has exactly one way out: `get_*` for
    /// the keys a caller holds in memory, and `write_luks_keyfile` for the
    /// LUKS pair, which leaves only as a file.
    pub(crate) fn expand_purpose<const N: usize>(
        &self,
        purpose: KeyPurpose,
        epoch: u64,
    ) -> [u8; N] {
        let hk = Hkdf::<Sha256>::new(Some(PURPOSE_DERIVE_SALT), &self.root_key);
        let mut info = purpose.domain_separator();
        info.extend_from_slice(&epoch.to_be_bytes());
        let mut derived = [0u8; N];
        hk.expand(&info, &mut derived)
            .expect("N is far below HKDF-SHA256's 255 * 32 byte output limit");
        derived
    }

    pub fn get_tx_io_sk(&self, epoch: u64) -> secp256k1::SecretKey {
        let key: [u8; 32] = self.expand_purpose(KeyPurpose::TxIo, epoch);
        secp256k1::SecretKey::from_slice(&key)
            .expect("retrieved secp256k1 secret key should be valid")
    }

    /// Retrieves the secp256k1 public key corresponding to the TxIo secret key.
    pub fn get_tx_io_pk(&self, epoch: u64) -> secp256k1::PublicKey {
        let key: [u8; 32] = self.expand_purpose(KeyPurpose::TxIo, epoch);
        let sk = secp256k1::SecretKey::from_slice(&key)
            .expect("retrieved secp256k1 secret key should be valid");

        secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &sk)
    }

    /// Derives the 64 bytes of HKDF input key material that seed the RNG
    /// precompile (0x64). The precompile re-derives from them on every call,
    /// so these bytes are consensus for the network's lifetime.
    pub fn get_rng_ikm(&self, epoch: u64) -> [u8; 64] {
        self.expand_purpose(KeyPurpose::RngPrecompile, epoch)
    }

    /// Retrieves the AES-256-GCM encryption key used for snapshot operations.
    pub fn get_snapshot_key(&self, epoch: u64) -> aes_gcm::Key<aes_gcm::Aes256Gcm> {
        let key: [u8; 32] = self.expand_purpose(KeyPurpose::Snapshot, epoch);
        key.into()
    }
}
