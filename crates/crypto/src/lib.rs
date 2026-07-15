use aes_gcm::{
    Aes256Gcm, Key,
    aead::{Aead, KeyInit, Payload},
};
use anyhow::anyhow;
use hkdf::Hkdf;
pub use schnorrkel::keys::Keypair as SchnorrkelKeypair;
use schnorrkel::{ExpansionMode, MiniSecretKey};
// Re-exported so consumers version-match the secp256k1 this crate's API
// exposes (`derive_aes_key` takes its `SharedSecret`; the sample-key fns
// return its key types).
pub use secp256k1;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey, ecdh::SharedSecret, ecdsa::Signature};
use sha2::{Digest, Sha256};
use std::{fs, io::Read, io::Write};
use std::{path::Path, str::FromStr};

use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::digest::{consts::U12, generic_array::GenericArray};

pub const AESGCM_NONCE_SIZE: usize = 12; // Size of AES-GCM nonce in bytes

/// The intermediate type to represent a nonce in the enclave
#[derive(Debug, Serialize, Deserialize, Clone)]
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

/// Converts a `u64` nonce to a `GenericArray<u8, N>`, where `N` is the size expected by AES-GCM.
///
/// This function takes a `u64` nonce and converts it into a generic byte array
/// with the appropriate size for AES-GCM encryption.
///
/// # Arguments
/// * `nonce` - A 64-bit unsigned integer representing the nonce.
///
/// # Returns
/// A `GenericArray<u8, N>` where `N` is the expected nonce size for AES-GCM encryption.
pub fn u64_to_be_bytes_array(nonce: u64) -> [u8; AESGCM_NONCE_SIZE] {
    let nonce_bytes = nonce.to_be_bytes().to_vec();
    let mut padded_nonce_bytes = [0u8; AESGCM_NONCE_SIZE];
    padded_nonce_bytes[AESGCM_NONCE_SIZE - nonce_bytes.len()..].copy_from_slice(&nonce_bytes);
    padded_nonce_bytes
}

/// Encrypts plaintext using AES-256 GCM with a 92-bit nonce.
///
/// This function requires the nonce to be exactly 92 bits (12 bytes),
/// with no padding or truncation. The caller must pass a `Vec<u8>`
/// containing 12 bytes.
///
/// # Arguments
/// * `key` - The AES-256 GCM key used for encryption.
/// * `plaintext` - The slice of bytes to encrypt.
/// * `nonce` - A `Nonce` containing exactly 12 bytes (92 bits).
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
    let nonce_array: Nonce = nonce.into();
    let cipher = Aes256Gcm::new(key);
    cipher
        .encrypt(&nonce_array.into(), plaintext)
        .map_err(|e| anyhow!("AES encryption failed: {:?}", e))
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
/// * `nonce` - A `Nonce` containing exactly 12 bytes (92 bits).
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

/// Decrypts ciphertext using AES-256 GCM with a 92-bit nonce.
///
/// This function requires the nonce to be exactly 92 bits (12 bytes),
/// with no padding or truncation. The caller must pass a `Vec<u8>`
/// containing 12 bytes.
///
/// # Arguments
/// * `key` - The AES-256 GCM key used for decryption.
/// * `ciphertext` - A slice of bytes (`&[u8]`) representing the encrypted data.
/// * `nonce` - A `Nonce` containing exactly 12 bytes (92 bits).
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
    let nonce_array: Nonce = nonce.into();
    let cipher = Aes256Gcm::new(key);

    cipher
        .decrypt(&nonce_array.into(), ciphertext)
        .map_err(|_| anyhow!("AES decryption failed. Authentication tag does not match the given ciphertext/nonce"))
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
/// * `nonce` - A `Nonce` containing exactly 12 bytes (92 bits).
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

/// Domain-separation registry for every AES key derived from an ECDH shared
/// secret. One variant per protocol context; [`derive_aes_key`] is the only
/// HKDF-expand over this input-keying-material class, so this enum is the
/// exhaustive list of its labels.
///
/// Two derived keys are independent unless both the shared secret AND the
/// label match. Keeping labels distinct per context makes key independence a
/// structural property rather than an assumption about which keypairs are
/// (re)used where — including adversarially, via the on-chain ECDH precompile,
/// which lets any contract evaluate the [`EcdhPrecompile`](Self::EcdhPrecompile)
/// derivation on caller-chosen keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AesKeyDomain {
    /// Client-to-TEE transaction I/O: encrypted calldata and signed-read
    /// requests. Clients encrypt, TEEs decrypt.
    TxRequest,
    /// TEE-to-client transaction I/O: signed-read return data. TEEs encrypt,
    /// clients decrypt. Independent from [`TxRequest`](Self::TxRequest) so a
    /// request/response pair can carry one public nonce without repeating an
    /// AES-GCM `(key, nonce)` pair.
    TxResponse,
    /// The ECDH precompile's on-chain key derivation. Consensus-frozen: its
    /// output is observable by contracts, so this label can never change, and
    /// no other domain may ever reuse it.
    EcdhPrecompile,
    /// The enclave-to-enclave root-key bootstrap handshake. Both sides ship
    /// in the same release and nothing wrapped is persisted, so this label
    /// (unlike the precompile's) can rotate with a coordinated upgrade.
    RootKeyWrap,
}

impl AesKeyDomain {
    const fn hkdf_info(self) -> &'static [u8] {
        match self {
            Self::TxRequest => b"seismic/request/aes-256-gcm/v1",
            Self::TxResponse => b"seismic/response/aes-256-gcm/v1",
            // Cannot change: live on testnet. Contracts observe (and may
            // persist data keyed by) this precompile's output, and no fork
            // can make data derived under an old label reachable again.
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

/// Signs a message digest using the provided Secp256k1 secret key.
///
/// This function first hashes the provided message using SHA-256 to create a digest,
/// then signs the resulting hash using the given `SecretKey`. The signature is returned
/// in compact form as a `Vec<u8>`.
///
/// # Arguments
///
/// * `msg` - A byte slice representing the message to be signed.
/// * `key` - The `SecretKey` used to sign the hashed message.
///
/// # Returns
///
/// This function returns a `Result` containing:
/// * `Ok(Vec<u8>)` - A vector containing the compact serialized signature on success.
/// * `Err(secp256k1::Error)` - An error if signing fails (e.g., if the message digest is invalid).
pub fn secp256k1_sign_digest(msg: &[u8], key: SecretKey) -> Result<Vec<u8>, secp256k1::Error> {
    // Create a Secp256k1 context for signing
    let secp = Secp256k1::signing_only();

    // Hash the message using SHA256
    let hash = Sha256::digest(msg);
    let hash_bytes: [u8; 32] = hash.into();
    let message = Message::from_digest(hash_bytes);

    // Sign the message with the secret key
    let signature = secp.sign_ecdsa(&message, &key);

    // Return the signature as a byte vector
    Ok(signature.serialize_compact().to_vec())
}

/// Verifies a Secp256k1 signature for a given message and public key.
///
/// This function hashes the message using SHA-256 to create a digest, then verifies
/// the provided signature using the corresponding `PublicKey`. The signature must be
/// in compact form (64 bytes).
///
/// # Arguments
///
/// * `msg` - A byte slice representing the original message.
/// * `sig` - A byte slice containing the compact serialized signature to verify.
/// * `pubkey` - The `PublicKey` used to verify the signature.
///
/// # Returns
///
/// This function returns a `Result` containing:
/// * `Ok(true)` - If the signature is valid for the provided message and public key.
/// * `Ok(false)` - If the signature is invalid.
/// * `Err(secp256k1::Error)` - If verification fails due to an invalid message,
pub fn secp256k1_verify(
    msg: &[u8],
    sig: &[u8],
    pubkey: PublicKey,
) -> Result<bool, secp256k1::Error> {
    // Create a Secp256k1 context for verification
    let secp = Secp256k1::verification_only();

    // Hash the message using SHA256
    let hash = Sha256::digest(msg);
    let hash_bytes: [u8; 32] = hash.into();
    let message = Message::from_digest(hash_bytes);

    // Deserialize the signature from a compact format
    let signature = Signature::from_compact(sig)?;

    // Verify the signature with the public key
    match secp.verify_ecdsa(&message, &signature, &pubkey) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Returns a sample Secp256k1 secret key for testing purposes.
pub fn get_unsecure_sample_secp256k1_sk() -> secp256k1::SecretKey {
    secp256k1::SecretKey::from_str(
        "311d54d3bf8359c70827122a44a7b4458733adce3c51c6b59d9acfce85e07505",
    )
    .unwrap()
}

/// Returns a sample Secp256k1 public key for testing purposes.
pub fn get_unsecure_sample_secp256k1_pk() -> secp256k1::PublicKey {
    secp256k1::PublicKey::from_str(
        "028e76821eb4d77fd30223ca971c49738eb5b5b71eabe93f96b348fdce788ae5a0",
    )
    .unwrap()
}

/// Returns a sample SchnorrkelKeypair public key for testing purposes.
pub fn get_unsecure_sample_schnorrkel_keypair() -> SchnorrkelKeypair {
    let mini_secret_key = MiniSecretKey::from_bytes(&[
        221, 143, 4, 149, 139, 56, 101, 208, 232, 50, 47, 39, 112, 211, 4, 111, 63, 63, 202, 141,
        138, 195, 190, 41, 139, 177, 214, 90, 176, 210, 173, 14,
    ])
    .unwrap();
    mini_secret_key.expand(ExpansionMode::Uniform).into()
}

/// Returns a sample AES key for testing purposes.
pub fn get_unsecure_sample_aesgcm_key() -> aes_gcm::Key<aes_gcm::Aes256Gcm> {
    let key: aes_gcm::Key<aes_gcm::Aes256Gcm> = [0u8; 32].into();
    key
}

/// Encrypts the provided data using an AES key derived from
/// the provided public key and the provided private key
pub fn ecdh_encrypt(
    pk: &PublicKey,
    sk: &SecretKey,
    domain: AesKeyDomain,
    data: &[u8],
    nonce: impl Into<Nonce>,
) -> Result<Vec<u8>, anyhow::Error> {
    let shared_secret = SharedSecret::new(pk, sk);
    let aes_key = derive_aes_key(&shared_secret, domain)
        .map_err(|e| anyhow!("Error deriving AES key: {:?}", e))?;
    let encrypted_data = aes_encrypt(&aes_key, data, nonce)?;
    Ok(encrypted_data)
}

/// Decrypts the provided data using a domain-separated AES key derived from
/// the provided public key and the provided private key.
pub fn ecdh_decrypt(
    pk: &PublicKey,
    sk: &SecretKey,
    domain: AesKeyDomain,
    data: &[u8],
    nonce: impl Into<Nonce>,
) -> Result<Vec<u8>, anyhow::Error> {
    let shared_secret = SharedSecret::new(pk, sk);
    let aes_key = derive_aes_key(&shared_secret, domain)
        .map_err(|e| anyhow!("Error deriving AES key: {:?}", e))?;
    let decrypted_data = aes_decrypt(&aes_key, data, nonce)?;
    Ok(decrypted_data)
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

/// Encrypts a file using the provided AES key and saves the output with an embedded nonce.
///
/// This function reads the contents of the input file, generates a random nonce,
/// encrypts the data using AES-GCM, and writes the nonce followed by the ciphertext
/// into the specified output file. The nonce is required for decryption and must
/// be stored along with the ciphertext.
///
/// # Arguments
/// * `input_path` - Path to the plaintext input file.
/// * `output_path` - Path where the encrypted file (nonce + ciphertext) will be written.
/// * `key` - AES-256-GCM key used for encryption.
///
/// # Returns
/// Returns `Ok(())` on success, or an error if reading, encryption, or writing fails.
pub fn encrypt_file(
    input_path: &str,
    output_path: &str,
    key: &Key<Aes256Gcm>,
) -> Result<(), anyhow::Error> {
    let plaintext = fs::read(input_path)
        .map_err(|e| anyhow::anyhow!("Failed to read input file {}: {:?}", input_path, e))?;

    // Generate a random nonce
    let nonce = Nonce::new_rand();

    // Encrypt the data
    let ciphertext = aes_encrypt(key, &plaintext, nonce.clone()).expect("Encryption failed!");

    // Get the parent directory and create it if it doesn't exist
    if let Some(parent) = Path::new(output_path).parent() {
        fs::create_dir_all(parent)?;
    }

    // Save nonce + ciphertext together
    let mut output_file = fs::File::create(output_path)
        .map_err(|e| anyhow::anyhow!("Failed to create output file {}: {:?}", output_path, e))?;
    output_file.write_all(&nonce.0)?; // Write nonce first
    output_file.write_all(&ciphertext)?; // Write encrypted content

    Ok(())
}

// Decrypts a file previously encrypted with `encrypt_file`, using the provided AES key.
///
/// This function reads the encrypted file, extracts the nonce (prepended during encryption),
/// decrypts the ciphertext using AES-GCM, and writes the decrypted plaintext to the specified output path.
///
/// # Arguments
/// * `input_path` - Path to the encrypted file (must contain nonce + ciphertext).
/// * `output_path` - Path where the decrypted file content will be written.
/// * `key` - AES-256-GCM key used for decryption.
///
/// # Returns
/// Returns `Ok(())` on success, or an error if reading, decryption, or writing fails.
pub fn decrypt_file(
    input_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
    key: &Key<Aes256Gcm>,
) -> Result<(), anyhow::Error> {
    let input_path = input_path.as_ref();
    let output_path = output_path.as_ref();

    let mut file = fs::File::open(input_path)
        .map_err(|e| anyhow::anyhow!("Failed to open input file {:?}: {:?}", input_path, e))?;
    let mut file_data = Vec::new();
    file.read_to_end(&mut file_data)?;

    // Extract nonce (first 12 bytes)
    if file_data.len() < AESGCM_NONCE_SIZE {
        anyhow::bail!("File is too small to contain a nonce!");
    }
    let nonce_bytes: [u8; AESGCM_NONCE_SIZE] = file_data[..AESGCM_NONCE_SIZE]
        .try_into()
        .map_err(|e| anyhow::anyhow!("Unexpected error casting nonce bytes: {:?}", e))?;
    let ciphertext = &file_data[AESGCM_NONCE_SIZE..];

    // Decrypt
    let decrypted_data = aes_decrypt(key, ciphertext, nonce_bytes)?;

    fs::write(output_path, decrypted_data)
        .map_err(|e| anyhow::anyhow!("Failed to write output file {:?}: {:?}", output_path, e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
                AesKeyDomain::TxRequest,
                "d958b910e65af59475e767c5fdcb8b2e3388b5d8aa2fbfaa01c08c422be6fd07",
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

    #[test]
    fn request_and_response_keys_are_distinct() {
        let shared_secret = SharedSecret::new(
            &get_unsecure_sample_secp256k1_pk(),
            &get_unsecure_sample_secp256k1_sk(),
        );

        let request_key = derive_aes_key(&shared_secret, AesKeyDomain::TxRequest).unwrap();
        let response_key = derive_aes_key(&shared_secret, AesKeyDomain::TxResponse).unwrap();

        assert_ne!(request_key.as_slice(), response_key.as_slice());
    }

    #[test]
    fn ciphertext_cannot_be_opened_in_the_other_direction() {
        let shared_secret = SharedSecret::new(
            &get_unsecure_sample_secp256k1_pk(),
            &get_unsecure_sample_secp256k1_sk(),
        );
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
