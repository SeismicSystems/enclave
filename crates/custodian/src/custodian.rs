use anyhow::Result;
use hkdf::Hkdf;
use rand::{TryRngCore as _, rngs::OsRng};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Salt used during HKDF key derivation for purpose-specific keys.
const PURPOSE_DERIVE_SALT: &[u8] = b"seismic-purpose-derive-salt";
/// Prefix used in domain separation when deriving purpose-specific keys.
const PREFIX: &str = "seismic-purpose";

#[derive(Zeroize, ZeroizeOnDrop, Clone)]
pub struct Key([u8; 32]);

impl AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Holder of the network root key; every other secret is derived from it on
/// demand. Deliberately not `Clone`: exactly one copy per process, dropped
/// (and zeroized) with the custodian itself.
pub struct Custodian {
    pub(crate) root_key: Key,
}

/// Enum representing the intended usage ("purpose") of a derived key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyPurpose {
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
    pub fn domain_separator(&self) -> Vec<u8> {
        format!("{PREFIX}-{}", self.label()).into_bytes()
    }
}

impl Custodian {
    /// Install an already-obtained root key (the joining-node path: the caller
    /// ran the attested bootstrap handshake and unwrapped the peer's response).
    pub fn new(root_key: [u8; 32]) -> Self {
        Self {
            root_key: Key(root_key),
        }
    }

    /// Generate a fresh root key from the OS CSPRNG (the genesis-node path).
    pub fn new_as_genesis() -> Result<Self> {
        let mut rng = OsRng;
        let mut rng_bytes = [0u8; 32];
        rng.try_fill_bytes(&mut rng_bytes)?;

        let km = Custodian::new(rng_bytes);
        Ok(km)
    }

    /// Derives a key for a specific `KeyPurpose`
    ///
    /// # Errors
    ///
    /// Returns an error if HKDF expansion fails (though this is unlikely with correct parameters).
    pub fn derive_purpose_key(&self, purpose: KeyPurpose, epoch: u64) -> Result<Key> {
        let hk = Hkdf::<Sha256>::new(Some(PURPOSE_DERIVE_SALT), self.root_key.0.as_ref());
        let mut info = purpose.domain_separator();
        info.extend_from_slice(&epoch.to_be_bytes());
        let mut derived_key = vec![0u8; 32];
        hk.expand(&info, &mut derived_key)
            .expect("32 is a valid length for Sha256 to output");
        let key = Key(derived_key.try_into().expect("unfallible"));

        Ok(key)
    }

    pub fn get_tx_io_sk(&self, epoch: u64) -> secp256k1::SecretKey {
        let key = self
            .derive_purpose_key(KeyPurpose::TxIo, epoch)
            .expect("purpose key derivation must succeed");
        secp256k1::SecretKey::from_slice(key.as_ref())
            .expect("retrieved secp256k1 secret key should be valid")
    }

    /// Retrieves the secp256k1 public key corresponding to the TxIo secret key.
    pub fn get_tx_io_pk(&self, epoch: u64) -> secp256k1::PublicKey {
        let key = self
            .derive_purpose_key(KeyPurpose::TxIo, epoch)
            .expect("purpose key derivation must succeed");
        let sk = secp256k1::SecretKey::from_slice(key.as_ref())
            .expect("retrieved secp256k1 secret key should be valid");

        secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &sk)
    }

    /// Retrieves the Schnorrkel keypair used for randomness generation.
    pub fn get_rng_keypair(&self, epoch: u64) -> schnorrkel::keys::Keypair {
        let mini_key = self
            .derive_purpose_key(KeyPurpose::RngPrecompile, epoch)
            .expect("purpose key derivation must succeed");
        let mini_key_bytes = mini_key.as_ref();
        let mini_secret_key = schnorrkel::MiniSecretKey::from_bytes(mini_key_bytes)
            .expect("mini_secret_key should be valid");
        mini_secret_key
            .expand(schnorrkel::ExpansionMode::Uniform)
            .into()
    }

    /// Retrieves the AES-256-GCM encryption key used for snapshot operations.
    pub fn get_snapshot_key(&self, epoch: u64) -> aes_gcm::Key<aes_gcm::Aes256Gcm> {
        let key = self
            .derive_purpose_key(KeyPurpose::Snapshot, epoch)
            .expect("purpose key derivation must succeed");
        let bytes: [u8; 32] = key.as_ref().try_into().expect("Key should be 32 bytes");
        bytes.into()
    }
}
