use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, AeadCore, KeyInit},
    Aes256Gcm, Key,
};
use anyhow::anyhow;
use hkdf::Hkdf;
use secp256k1::{ecdh::SharedSecret, ecdsa::Signature, Message, PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::str::FromStr;

#[derive(Serialize, Deserialize)]
pub struct Secp256k1KeyPair {
    pub secret_key: SecretKey,
    pub public_key: PublicKey,
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
pub fn u64_to_generic_u8_array(nonce: u64) -> GenericArray<u8, <Aes256Gcm as AeadCore>::NonceSize> {
    let mut nonce_bytes = nonce.to_be_bytes().to_vec();
    let crypto_nonce_size = GenericArray::<u8, <Aes256Gcm as AeadCore>::NonceSize>::default().len();
    nonce_bytes.resize(crypto_nonce_size, 0); // pad to the expected size
    GenericArray::clone_from_slice(&nonce_bytes)
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
/// * `nonce` - A `Vec<u8>` containing exactly 12 bytes (92 bits).
///
/// # Returns
/// A `Vec<u8>` containing the bytes of encrypted ciphertext.
///
/// # Errors
/// Returns an error if the nonce size is incorrect or if encryption fails.
pub fn aes_encrypt(
    key: &Key<Aes256Gcm>,
    plaintext: &[u8],
    nonce: Vec<u8>,
) -> anyhow::Result<Vec<u8>> {
    if nonce.len() != 12 {
        return Err(anyhow!("Nonce must be exactly 12 bytes (92 bits)"));
    }
    let nonce_array = GenericArray::<u8, <Aes256Gcm as AeadCore>::NonceSize>::clone_from_slice(&nonce);
    let cipher = Aes256Gcm::new(key);
    cipher
        .encrypt(&nonce_array, plaintext)
        .map_err(|e| anyhow!("AES encryption failed: {:?}", e))
}

/// Decrypts ciphertext using AES-256 GCM with the provided key and nonce.
///
/// This function uses AES-GCM to decrypt a ciphertext into a Vec<u8>.
/// It expects the ciphertext to be a slice of bytes
///
/// # Arguments
/// * `key` - The AES-256 GCM key used for decryption.
/// * `ciphertext` - A slice of bytes (`&[u8]`) representing the encrypted data.
/// * `nonce` - A 64-bit unsigned integer used as the nonce for decryption.
///
/// # Returns
/// A `Vec<u8>` containing the bytes of the decrypted plaintext
///
/// # Panics
/// This function will panic if decryption or decoding fails.
pub fn aes_decrypt(key: &Key<Aes256Gcm>, ciphertext: &[u8], nonce: u64) -> anyhow::Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key);
    let nonce = u64_to_generic_u8_array(nonce);

    let plaintext = cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|e| anyhow!("AES decryption failed: {:?}", e))?;
    Ok(plaintext)
}

/// Derives an AES key from a shared secret using HKDF and SHA-256.
///
/// This function takes a `SharedSecret` and derives a 256-bit AES key using
/// the HKDF (HMAC-based Extract-and-Expand Key Derivation Function) with SHA-256.
///
/// # Arguments
/// * `shared_secret` - The shared secret from which the AES key will be derived.
///
/// # Returns
/// A `Result` containing the derived AES key, or an error if key derivation fails.
pub fn derive_aes_key(shared_secret: &SharedSecret) -> Result<Key<Aes256Gcm>, hkdf::InvalidLength> {
    // Initialize HKDF with SHA-256
    let hk = Hkdf::<Sha256>::new(None, &shared_secret.secret_bytes());

    // Output a 32-byte key for AES-256
    let mut okm = [0u8; 32];
    hk.expand(b"aes-gcm key", &mut okm)?;
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
pub fn get_sample_secp256k1_sk() -> secp256k1::SecretKey {
    secp256k1::SecretKey::from_str(
        "311d54d3bf8359c70827122a44a7b4458733adce3c51c6b59d9acfce85e07505",
    )
    .unwrap()
}

/// Returns a sample Secp256k1 public key for testing purposes.
pub fn get_sample_secp256k1_pk() -> secp256k1::PublicKey {
    secp256k1::PublicKey::from_str(
        "028e76821eb4d77fd30223ca971c49738eb5b5b71eabe93f96b348fdce788ae5a0",
    )
    .unwrap()
}
