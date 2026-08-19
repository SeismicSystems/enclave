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

impl Key {
    /// Wrap 32 bytes of key material obtained outside the derivation path
    /// (e.g. a council-delivered epoch key). The caller is responsible for
    /// zeroizing its own copy of `bytes`.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Interpret the key as a secp256k1 secret scalar and return the keypair.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are zero or exceed the curve order.
    pub fn to_secp256k1_keypair(&self) -> Result<(secp256k1::SecretKey, secp256k1::PublicKey)> {
        let sk = secp256k1::SecretKey::from_slice(&self.0)?;
        let pk = secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &sk);
        Ok((sk, pk))
    }

    /// Expand the key into the 64 bytes of RNG-precompile input key material
    /// via the schnorrkel mini-secret expansion (see the compatibility note
    /// on [`Custodian::get_rng_ikm`]).
    pub fn to_rng_ikm(&self) -> Result<[u8; 64]> {
        let mini_secret_key = schnorrkel::MiniSecretKey::from_bytes(&self.0)
            .map_err(|e| anyhow::anyhow!("invalid schnorrkel mini secret: {e}"))?;
        Ok(mini_secret_key
            .expand(schnorrkel::ExpansionMode::Uniform)
            .to_bytes())
    }

    /// Interpret the key as an AES-256-GCM snapshot encryption key.
    pub fn to_snapshot_key(&self) -> aes_gcm::Key<aes_gcm::Aes256Gcm> {
        self.0.into()
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
        key.to_secp256k1_keypair()
            .expect("retrieved secp256k1 secret key should be valid")
            .0
    }

    /// Retrieves the secp256k1 public key corresponding to the TxIo secret key.
    pub fn get_tx_io_pk(&self, epoch: u64) -> secp256k1::PublicKey {
        let key = self
            .derive_purpose_key(KeyPurpose::TxIo, epoch)
            .expect("purpose key derivation must succeed");
        key.to_secp256k1_keypair()
            .expect("retrieved secp256k1 secret key should be valid")
            .1
    }

    /// Derives the 64 bytes of HKDF input key material that seed the RNG
    /// precompile: the secret half of a schnorrkel keypair expanded from the
    /// purpose-derived mini secret.
    // TODO: the schnorrkel mini-secret expansion is kept only for backward
    // compatibility with the running testnet — the expansion determines the
    // derived bytes, and the RNG precompile's outputs are consensus. On the
    // next network reset, drop it and take the ikm straight from the purpose
    // derivation: have `derive_purpose_key` expand 64 bytes here instead of
    // 32, removing schnorrkel from the custodian.
    pub fn get_rng_ikm(&self, epoch: u64) -> [u8; 64] {
        let mini_key = self
            .derive_purpose_key(KeyPurpose::RngPrecompile, epoch)
            .expect("purpose key derivation must succeed");
        mini_key
            .to_rng_ikm()
            .expect("mini_secret_key should be valid")
    }

    /// Retrieves the AES-256-GCM encryption key used for snapshot operations.
    pub fn get_snapshot_key(&self, epoch: u64) -> aes_gcm::Key<aes_gcm::Aes256Gcm> {
        self.derive_purpose_key(KeyPurpose::Snapshot, epoch)
            .expect("purpose key derivation must succeed")
            .to_snapshot_key()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT_KEY: [u8; 32] = [7u8; 32];

    /// The `Custodian::get_*` accessors must equal derive-then-convert on
    /// `Key`, so keys delivered from outside the derivation path (council
    /// deliveries) go through the exact same conversions as derived ones.
    #[test]
    fn custodian_accessors_match_key_conversions() {
        let custodian = Custodian::new(ROOT_KEY);
        for epoch in [0u64, 1, 7] {
            let tx_io = custodian
                .derive_purpose_key(KeyPurpose::TxIo, epoch)
                .unwrap();
            let (sk, pk) = tx_io.to_secp256k1_keypair().unwrap();
            assert_eq!(sk, custodian.get_tx_io_sk(epoch));
            assert_eq!(pk, custodian.get_tx_io_pk(epoch));

            let rng = custodian
                .derive_purpose_key(KeyPurpose::RngPrecompile, epoch)
                .unwrap();
            assert_eq!(rng.to_rng_ikm().unwrap(), custodian.get_rng_ikm(epoch));

            let snapshot = custodian
                .derive_purpose_key(KeyPurpose::Snapshot, epoch)
                .unwrap();
            assert_eq!(
                snapshot.to_snapshot_key(),
                custodian.get_snapshot_key(epoch)
            );
        }
    }

    #[test]
    fn invalid_scalar_key_converts_to_error_not_panic() {
        // 32 bytes of 0xff exceed the secp256k1 curve order.
        assert!(Key::new([0xff; 32]).to_secp256k1_keypair().is_err());
    }
}
