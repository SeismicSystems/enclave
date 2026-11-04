use aes_gcm::{
    Aes256Gcm, Key,
    aead::{Aead, KeyInit, Payload},
};
use anyhow::anyhow;
use hkdf::Hkdf;
// Re-exported so consumers version-match the secp256k1 whose types this
// crate's API exposes.
pub use secp256k1;
use secp256k1::{PublicKey, Secp256k1, SecretKey, ecdh::SharedSecret};
use sha2::Sha256;
use std::str::FromStr;

use rand::RngCore;
use sha2::digest::{consts::U12, generic_array::GenericArray};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const AESGCM_NONCE_SIZE: usize = 12; // Size of AES-GCM nonce in bytes

/// The intermediate type to represent a nonce in the enclave
#[derive(Debug, Clone)]
pub struct Nonce(pub [u8; AESGCM_NONCE_SIZE]);

impl Nonce {
    pub fn new_rand() -> Self {
        let mut rng = rand::rng();
        // Generate a random U96 value
        let mut bytes = [0u8; 12]; // 96 bits = 12 bytes
        rng.fill_bytes(&mut bytes);
        Nonce(bytes)
    }
}

impl From<Nonce> for aes_gcm::Nonce<U12> {
    fn from(nonce: Nonce) -> Self {
        GenericArray::clone_from_slice(&nonce.0)
    }
}

impl From<[u8; AESGCM_NONCE_SIZE]> for Nonce {
    fn from(bytes: [u8; AESGCM_NONCE_SIZE]) -> Self {
        Nonce(bytes)
    }
}

/// Encrypts plaintext using AES-256 GCM with a 96-bit nonce.
///
/// Equivalent to [`aes_encrypt_aead`] with empty AAD: GCM with empty AAD
/// produces byte-identical output. The AES-GCM encrypt precompile calls this,
/// so its output is consensus; a test pins it.
///
/// # Arguments
/// * `key` - The AES-256 GCM key used for encryption.
/// * `plaintext` - The slice of bytes to encrypt.
/// * `nonce` - A `Nonce` containing exactly 12 bytes (96 bits).
///
/// # Returns
/// A `Vec<u8>` containing the bytes of encrypted ciphertext.
///
/// # Errors
/// Returns an error if the nonce size is incorrect or if encryption fails.
pub fn aes_encrypt(
    key: &Key<Aes256Gcm>,
    plaintext: &[u8],
    nonce: impl Into<Nonce>,
) -> anyhow::Result<Vec<u8>> {
    aes_encrypt_aead(key, plaintext, nonce, &[])
}

/// Encrypts plaintext using AES-256 GCM with AEAD (authenticated encryption with additional data).
///
/// This function provides authenticated encryption where both the plaintext and additional
/// authenticated data (AAD) are cryptographically protected. The AAD is not encrypted but
/// its integrity is verified during decryption.
///
/// # Arguments
/// * `key` - The AES-256 GCM key used for encryption.
/// * `plaintext` - The slice of bytes to encrypt.
/// * `nonce` - A `Nonce` containing exactly 12 bytes (96 bits).
/// * `aad` - Additional authenticated data that will be authenticated but not encrypted.
///
/// # Returns
/// A `Vec<u8>` containing the bytes of encrypted ciphertext with authentication tag.
///
/// # Errors
/// Returns an error if the nonce size is incorrect or if encryption fails.
pub fn aes_encrypt_aead(
    key: &Key<Aes256Gcm>,
    plaintext: &[u8],
    nonce: impl Into<Nonce>,
    aad: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let nonce_array: Nonce = nonce.into();
    let cipher = Aes256Gcm::new(key);
    cipher
        .encrypt(
            &nonce_array.into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| anyhow!("AES-AEAD encryption failed: {:?}", e))
}

/// Decrypts ciphertext using AES-256 GCM with a 96-bit nonce.
///
/// Equivalent to [`aes_decrypt_aead`] with empty AAD. The AES-GCM decrypt
/// precompile calls this, so its behavior is consensus.
///
/// # Arguments
/// * `key` - The AES-256 GCM key used for decryption.
/// * `ciphertext` - A slice of bytes (`&[u8]`) representing the encrypted data.
/// * `nonce` - A `Nonce` containing exactly 12 bytes (96 bits).
///
/// # Returns
/// A `Vec<u8>` containing the bytes of the decrypted plaintext.
///
/// # Errors
/// Returns an error if the nonce size is incorrect or if decryption fails.
pub fn aes_decrypt(
    key: &Key<Aes256Gcm>,
    ciphertext: &[u8],
    nonce: impl Into<Nonce>,
) -> anyhow::Result<Vec<u8>> {
    aes_decrypt_aead(key, ciphertext, nonce, &[])
}

/// Decrypts ciphertext using AES-256 GCM with AEAD (authenticated encryption with additional data).
///
/// This function provides authenticated decryption where both the ciphertext and additional
/// authenticated data (AAD) are cryptographically verified. The decryption will fail if
/// either the ciphertext or AAD have been tampered with.
///
/// # Arguments
/// * `key` - The AES-256 GCM key used for decryption.
/// * `ciphertext` - A slice of bytes representing the encrypted data with authentication tag.
/// * `nonce` - A `Nonce` containing exactly 12 bytes (96 bits).
/// * `aad` - Additional authenticated data that must match what was used during encryption.
///
/// # Returns
/// A `Vec<u8>` containing the bytes of the decrypted plaintext.
///
/// # Errors
/// Returns an error if decryption fails or if the authentication tag verification fails.
pub fn aes_decrypt_aead(
    key: &Key<Aes256Gcm>,
    ciphertext: &[u8],
    nonce: impl Into<Nonce>,
    aad: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let nonce_array: Nonce = nonce.into();
    let cipher = Aes256Gcm::new(key);

    cipher
        .decrypt(&nonce_array.into(), Payload { msg: ciphertext, aad })
        .map_err(|_| anyhow!("AES-AEAD decryption failed. Authentication tag does not match the given ciphertext/nonce/aad"))
}

/// Domain-separation labels for every AES key derived from an ECDH shared
/// secret. One variant per protocol context; [`derive_aes_key`] is the only
/// HKDF-expand over this input-keying-material class, so this enum is the
/// exhaustive list of its labels.
///
/// Two derived keys are independent unless both the shared secret AND the
/// label match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AesKeyDomain {
    /// Client-to-TEE transaction I/O: Clients encrypts calldata, TEEs decrypt.
    /// Use for both seismic txs and for signed-reads (eth_calls).
    /// Signed reads request and response share the same nonce (sent as part of the tx)
    /// and so must use a different domain.
    TxRequest,
    /// TEE-to-client transaction I/O: signed-read return data. TEEs encrypt,
    /// clients decrypt. Distinct from [`TxRequest`](Self::TxRequest) so a
    /// request/response pair sharing one public nonce never repeats an
    /// AES-GCM `(key, nonce)` pair — the separation the nonce-reuse fix needs.
    TxResponse,
    /// The ECDH precompile's on-chain key derivation. Also on the original
    /// `"aes-gcm key"` label, and consensus-frozen: its output is observable
    /// by contracts, so it can never change.
    EcdhPrecompile,
    /// The enclave-to-enclave root-key bootstrap handshake. Both sides ship
    /// in the same release and nothing wrapped is persisted, so this label
    /// can rotate with a coordinated upgrade.
    RootKeyWrap,
}

impl AesKeyDomain {
    const fn hkdf_info(self) -> &'static [u8] {
        match self {
            // Original pre domain-separation label, kept for backward compat and to
            // prevent a consensus breaking change (request path is decrypted in the block executor).
            // TxRequest and TxResponse MUST be different since they share the same key and nonce,
            // but its fine for TxRequest to share a label with the unrelated EcdhPrecompile with
            // which it doesn't share a key.
            Self::TxRequest => b"aes-gcm key",
            Self::TxResponse => b"seismic/response/aes-256-gcm/v1",
            // Same pre domain-separation label, kept for backward compatibility.
            // Shared with TxRequest; see above.
            Self::EcdhPrecompile => b"aes-gcm key",
            Self::RootKeyWrap => b"seismic/root-key-wrap/aes-256-gcm/v1",
        }
    }
}

/// Derives a domain-separated AES-256 key from an ECDH shared secret using
/// HKDF-SHA256. See [`AesKeyDomain`] for the label registry.
pub fn derive_aes_key(
    shared_secret: &SharedSecret,
    domain: AesKeyDomain,
) -> Result<Key<Aes256Gcm>, hkdf::InvalidLength> {
    let hk = Hkdf::<Sha256>::new(None, &shared_secret.secret_bytes());
    let mut okm = [0u8; 32];
    hk.expand(domain.hkdf_info(), &mut okm)?;
    Ok(*Key::<Aes256Gcm>::from_slice(&okm))
}

/// The well-known tx-io keypair for transaction encryption on networks
/// running the well-known keys: clients ECDH against the public half to
/// encrypt calldata, the node decrypts with the secret half.
///
/// The well-known keys serve networks with no root key to derive purpose keys
/// from — dev networks and pre-TEE deployments. They are published in this
/// public repository and provide no confidentiality against anyone who reads
/// the source; their only property is that every node and client agrees on
/// them.
pub fn well_known_tx_io_keypair() -> secp256k1::Keypair {
    let sk = secp256k1::SecretKey::from_str(
        "311d54d3bf8359c70827122a44a7b4458733adce3c51c6b59d9acfce85e07505",
    )
    .unwrap();
    secp256k1::Keypair::from_secret_key(&Secp256k1::new(), &sk)
}

/// HKDF input key material for the RNG precompile.
///
/// Opaque: holders feed it to HKDF and nothing interprets its structure. The
/// type exists so the bytes cannot be mixed up with the stack's other 64-byte
/// values (signatures, uncompressed public keys, curve points) and so every
/// holder gets a redacted `Debug` without writing one.
///
/// Zeroized on drop. Moves still leave stale, unwiped copies behind, since a
/// Rust move is a `memcpy`. That is accepted at ownership handoffs (custodian
/// to IPC, IPC to node, node to EVM): the key stays resident for a whole
/// epoch anyway, and wiping every intermediate copy would need a heap-pinned
/// handle threaded through every repo for no gain against an attacker who can
/// already read the live copy. Hot paths that only read the key, such as each
/// precompile call, should borrow it rather than copy it.
///
/// `==` is constant-time, so comparing two keys leaks nothing about where
/// they differ.
///
/// Not `Serialize`: wire formats carry their own byte DTO (e.g.
/// `seismic-custodian-ipc`'s `RngIkmBytes`) and convert at their boundary.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RngIkm([u8; Self::LEN]);

impl RngIkm {
    /// Length of the input key material in bytes.
    pub const LEN: usize = 64;

    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl PartialEq for RngIkm {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for RngIkm {}

impl std::fmt::Debug for RngIkm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RngIkm(<redacted>)")
    }
}

/// The well-known rng HKDF input key material: seeds the RNG precompile on
/// networks running the well-known keys.
///
/// The value is a consensus input — RNG-precompile outputs derive from it —
/// so these bytes are frozen; a test pins them against accidental edits.
pub fn well_known_rng_ikm() -> RngIkm {
    RngIkm::from_bytes(hex_literal::hex!(
        "6c8fd0805e9524e8f01fee6f3627f6a3e7beed894c136bbc4e857eb7f5323808"
        "796c7dd73ee7d470538d4b9a6de14a479bfec72a4f64565d9bbea5b5c7f9c372"
    ))
}

/// Encrypts the provided data using AEAD with a domain-separated AES key
/// derived from the provided public key and the provided private key.
pub fn ecdh_encrypt_aead(
    pk: &PublicKey,
    sk: &SecretKey,
    domain: AesKeyDomain,
    data: &[u8],
    nonce: impl Into<Nonce>,
    aad: &[u8],
) -> Result<Vec<u8>, anyhow::Error> {
    let shared_secret = SharedSecret::new(pk, sk);
    let aes_key = derive_aes_key(&shared_secret, domain)
        .map_err(|e| anyhow!("Error deriving AES key: {:?}", e))?;
    let encrypted_data = aes_encrypt_aead(&aes_key, data, nonce, aad)?;
    Ok(encrypted_data)
}

/// Decrypts the provided data using AEAD with a domain-separated AES key
/// derived from the provided public key and the provided private key.
pub fn ecdh_decrypt_aead(
    pk: &PublicKey,
    sk: &SecretKey,
    domain: AesKeyDomain,
    data: &[u8],
    nonce: impl Into<Nonce>,
    aad: &[u8],
) -> Result<Vec<u8>, anyhow::Error> {
    let shared_secret = SharedSecret::new(pk, sk);
    let aes_key = derive_aes_key(&shared_secret, domain)
        .map_err(|e| anyhow!("Error deriving AES key: {:?}", e))?;
    let decrypted_data = aes_decrypt_aead(&aes_key, data, nonce, aad)?;
    Ok(decrypted_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The published public half must never drift: clients on running
    /// networks encrypt to it.
    #[test]
    fn well_known_tx_io_pk_is_frozen() {
        assert_eq!(
            well_known_tx_io_keypair().public_key(),
            PublicKey::from_str(
                "028e76821eb4d77fd30223ca971c49738eb5b5b71eabe93f96b348fdce788ae5a0"
            )
            .unwrap()
        );
    }

    /// The ikm bytes are `schnorrkel::SecretKey::to_bytes()` (32-byte key ||
    /// 32-byte nonce) of the keypair expanded from this mini secret. No
    /// schnorrkel cryptography is performed anywhere with them — consumers
    /// feed them to HKDF only — but the value is consensus on every network
    /// running the well-known keys, so it must never drift.
    #[test]
    fn well_known_rng_ikm_is_the_frozen_expansion() {
        let mini_secret_key = schnorrkel::MiniSecretKey::from_bytes(&[
            221, 143, 4, 149, 139, 56, 101, 208, 232, 50, 47, 39, 112, 211, 4, 111, 63, 63, 202,
            141, 138, 195, 190, 41, 139, 177, 214, 90, 176, 210, 173, 14,
        ])
        .unwrap();
        let expanded = mini_secret_key.expand(schnorrkel::ExpansionMode::Uniform);
        assert_eq!(well_known_rng_ikm().as_bytes(), &expanded.to_bytes());
    }

    #[test]
    fn rng_ikm_debug_is_redacted() {
        let ikm = RngIkm::from_bytes([0xab; RngIkm::LEN]);
        assert_eq!(format!("{ikm:?}"), "RngIkm(<redacted>)");
    }

    #[test]
    fn rng_ikm_eq_compares_every_byte() {
        let ikm = RngIkm::from_bytes([0xab; RngIkm::LEN]);
        assert_eq!(ikm, RngIkm::from_bytes([0xab; RngIkm::LEN]));

        // A difference in the last byte must still count.
        let mut last_differs = [0xab; RngIkm::LEN];
        last_differs[RngIkm::LEN - 1] = 0xac;
        assert_ne!(ikm, RngIkm::from_bytes(last_differs));
    }

    /// Known-answer test shared with the TypeScript (aesKeygen.ts) and Python
    /// (test_crypto.py) client suites. All three languages must derive these
    /// exact keys from the same ECDH inputs; a label edit in any one of them
    /// fails its copy of this test.
    #[test]
    fn domain_key_derivation_matches_cross_language_vectors() {
        let client_sk =
            SecretKey::from_str("a30363336e1bb949185292a2a302de86e447d98f3a43d823c8c234d9e3e5ad77")
                .unwrap();
        let tee_pk = PublicKey::from_str(
            "028e76821eb4d77fd30223ca971c49738eb5b5b71eabe93f96b348fdce788ae5a0",
        )
        .unwrap();
        let shared_secret = SharedSecret::new(&tee_pk, &client_sk);
        assert_eq!(
            hex::encode(shared_secret.secret_bytes()),
            "46a4d6fce8eca748ba8362e726de51a5c62202c887d6bb81fa6f4df1fb360999"
        );

        let vectors = [
            (
                // Same as `EcdhPrecompile` below: both keep the original
                // `"aes-gcm key"` label (see `AesKeyDomain::TxRequest`).
                AesKeyDomain::TxRequest,
                "bf0dd6556618d1bf8d1602bf80be3a0f7cc729973829bb9acb75bd77770d5b90",
            ),
            (
                AesKeyDomain::TxResponse,
                "974b310e3990d555da33e2b0c1dc6036a9709400ec992dbfc9330cc00e673144",
            ),
            (
                AesKeyDomain::EcdhPrecompile,
                "bf0dd6556618d1bf8d1602bf80be3a0f7cc729973829bb9acb75bd77770d5b90",
            ),
            (
                AesKeyDomain::RootKeyWrap,
                "f48820f0d247f5841a1d91fe1c48f590e0172cac4bec879d2dcdf04e9d1f7647",
            ),
        ];
        for (domain, expected) in vectors {
            let key = derive_aes_key(&shared_secret, domain).unwrap();
            assert_eq!(hex::encode(key.as_slice()), expected, "{domain:?}");
        }
    }

    /// `aes_encrypt`/`aes_decrypt` back the AES-GCM precompiles, so their
    /// output is consensus. They now delegate to the AEAD variants with empty
    /// AAD; pin that against the standard AES-256-GCM test vectors (McGrew &
    /// Viega, "The Galois/Counter Mode of Operation", test cases 13 and 14)
    /// and against the cipher called directly with no AAD, which is what
    /// these functions did before delegating.
    #[test]
    fn non_aead_aes_matches_gcm_with_empty_aad() {
        let key = Key::<Aes256Gcm>::from_slice(&[0u8; 32]);
        let nonce = [0u8; AESGCM_NONCE_SIZE];

        // Test case 13: empty plaintext -> tag only.
        assert_eq!(
            hex::encode(aes_encrypt(key, &[], nonce).unwrap()),
            "530f8afbc74536b9a963b4f1c4cb738b"
        );
        // Test case 14: one zero block -> ciphertext || tag.
        assert_eq!(
            hex::encode(aes_encrypt(key, &[0u8; 16], nonce).unwrap()),
            "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919"
        );

        let key = Key::<Aes256Gcm>::from_slice(&[0x11; 32]);
        let nonce = [0x22; AESGCM_NONCE_SIZE];
        for len in [0, 1, 15, 16, 17, 64, 1000] {
            let plaintext: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let direct = Aes256Gcm::new(key)
                .encrypt(&Nonce(nonce).into(), plaintext.as_slice())
                .unwrap();

            let ciphertext = aes_encrypt(key, &plaintext, nonce).unwrap();
            assert_eq!(ciphertext, direct, "len {len}");
            assert_eq!(
                ciphertext,
                aes_encrypt_aead(key, &plaintext, nonce, &[]).unwrap(),
                "len {len}"
            );
            assert_eq!(aes_decrypt(key, &ciphertext, nonce).unwrap(), plaintext);
            assert_eq!(
                aes_decrypt_aead(key, &ciphertext, nonce, &[]).unwrap(),
                plaintext
            );
        }

        // A ciphertext bound to non-empty AAD must not open without it.
        let bound = aes_encrypt_aead(key, b"payload", nonce, b"aad").unwrap();
        assert!(aes_decrypt(key, &bound, nonce).is_err());
    }

    #[test]
    fn request_and_response_keys_are_distinct() {
        let keypair = well_known_tx_io_keypair();
        let shared_secret = SharedSecret::new(&keypair.public_key(), &keypair.secret_key());

        let request_key = derive_aes_key(&shared_secret, AesKeyDomain::TxRequest).unwrap();
        let response_key = derive_aes_key(&shared_secret, AesKeyDomain::TxResponse).unwrap();

        assert_ne!(request_key.as_slice(), response_key.as_slice());
    }

    /// The request path must keep the original `"aes-gcm key"` label: it is
    /// decrypted in the block executor, so a new label would be a consensus
    /// break. Pin it so it can't change without a deliberate, reviewed edit.
    #[test]
    fn request_keeps_the_original_label() {
        assert_eq!(AesKeyDomain::TxRequest.hkdf_info(), b"aes-gcm key");
    }

    #[test]
    fn ciphertext_cannot_be_opened_in_the_other_direction() {
        let keypair = well_known_tx_io_keypair();
        let shared_secret = SharedSecret::new(&keypair.public_key(), &keypair.secret_key());
        let request_key = derive_aes_key(&shared_secret, AesKeyDomain::TxRequest).unwrap();
        let response_key = derive_aes_key(&shared_secret, AesKeyDomain::TxResponse).unwrap();
        let nonce = [0x42; AESGCM_NONCE_SIZE];
        let aad = b"transaction metadata";
        let plaintext = b"request payload";

        let ciphertext = aes_encrypt_aead(&request_key, plaintext, nonce, aad).unwrap();

        assert!(aes_decrypt_aead(&response_key, &ciphertext, nonce, aad).is_err());
        assert_eq!(
            aes_decrypt_aead(&request_key, &ciphertext, nonce, aad).unwrap(),
            plaintext
        );
    }
}
