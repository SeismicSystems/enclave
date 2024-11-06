use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, AeadCore, KeyInit},
    Aes256Gcm, Key,
};
use alloy_rlp::{Decodable, Encodable};
use anyhow::anyhow;
use hkdf::Hkdf;
use secp256k1::{ecdh::SharedSecret, ecdsa::Signature, Message, PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::str::FromStr;

use openssl::encrypt::{Decrypter, Encrypter};
use openssl::pkey::{PKey, Private};
use openssl::rsa::{Padding, Rsa};

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

/// Encrypts plaintext using AES-256 GCM with the provided key and nonce.
///
/// This function uses AES-GCM to encrypt a serializable object (of type `Encodable`)
/// using the provided AES key and nonce. The object is first serialized to a `Vec<u8>`
/// and then encrypted.
///
/// # Arguments
/// * `key` - The AES-256 GCM key used for encryption.
/// * `plaintext` - The object to encrypt, which must implement the `Encodable` trait.
/// * `nonce` - A 64-bit unsigned integer used as the nonce for the encryption process.
///
/// # Returns
/// A `Vec<u8>` containing the encrypted ciphertext.
///
/// # Panics
/// This function will panic if the encryption fails.
pub fn aes_encrypt<T: Encodable>(key: &Key<Aes256Gcm>, plaintext: &T, nonce: u64) -> Vec<u8> {
    let cipher = Aes256Gcm::new(key);
    let nonce = u64_to_generic_u8_array(nonce);

    // convert the encodable object to a Vec<u8>
    let mut buf = Vec::new();
    plaintext.encode(&mut buf);

    // encrypt the Vec<u8>
    cipher
        .encrypt(&nonce, buf.as_ref())
        .unwrap_or_else(|err| panic!("Encryption failed: {:?}", err))
}

/// Decrypts ciphertext using AES-256 GCM with the provided key and nonce.
///
/// This function uses AES-GCM to decrypt a ciphertext into an object that implements
/// the `Decodable` trait. The function expects the ciphertext to be a `Vec<u8>`, and
/// it will return the deserialized object if the decryption is successful.
///
/// # Arguments
/// * `key` - The AES-256 GCM key used for decryption.
/// * `ciphertext` - A slice of bytes (`&[u8]`) representing the encrypted data.
/// * `nonce` - A 64-bit unsigned integer used as the nonce for decryption.
///
/// # Returns
/// The decrypted object of type `T`, where `T` implements the `Decodable` trait.
///
/// # Panics
/// This function will panic if decryption or decoding fails.
pub fn aes_decrypt<T>(
    key: &Key<Aes256Gcm>,
    ciphertext: &[u8],
    nonce: u64,
) -> Result<T, anyhow::Error>
where
    T: Decodable,
{
    let cipher = Aes256Gcm::new(key);
    let nonce = u64_to_generic_u8_array(nonce);

    // recover the plaintext byte encoding of the object
    let buf = cipher
        .decrypt(&nonce, ciphertext.as_ref())
        .map_err(|e| anyhow!("AES decryption failed: {:?}", e))?;

    // recover the object from the byte encoding
    let plaintext =
        T::decode(&mut &buf[..]).map_err(|e| anyhow!("Failed to decode plaintext: {:?}", e))?;

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

pub fn rsa_encrypt(plaintext: &[u8], public_key: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
    let rsa = Rsa::public_key_from_pem(public_key)?;
    let key = PKey::from_rsa(rsa)?;
    let mut encrypter = Encrypter::new(&key)?;
    encrypter.set_rsa_padding(Padding::PKCS1).unwrap();
    let buffer_len = encrypter.encrypt_len(plaintext).unwrap();
    let mut ciphertext: Vec<u8> = vec![0; buffer_len];
    let encrypted_len = encrypter.encrypt(plaintext, &mut ciphertext).unwrap();
    ciphertext.truncate(encrypted_len);
    Ok(ciphertext)
}

pub fn rsa_decrypt(ciphertext: &[u8], private_key: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
    let rsa = Rsa::private_key_from_pem(private_key)?;
    let key = PKey::from_rsa(rsa)?;
    let mut decrypter = Decrypter::new(&key)?;
    decrypter.set_rsa_padding(Padding::PKCS1).unwrap();
    let buffer_len = decrypter.decrypt_len(ciphertext).unwrap();
    let mut plaintext: Vec<u8> = vec![0; buffer_len];
    let decrypted_len = decrypter.decrypt(ciphertext, &mut plaintext).unwrap();
    plaintext.truncate(decrypted_len);
    Ok(plaintext)
}

pub fn get_sample_rsa() -> Rsa<Private> {
    // let rsa_keypair: Rsa<Private> = Rsa::generate(2048).unwrap();
    // let public_key = rsa_keypair.public_key_to_pem().unwrap();
    // let private_key = rsa_keypair.private_key_to_pem().unwrap();

    // println!("{:?}", public_key);
    // println!("{:?}", private_key);

    let private_key_pem: Vec<u8> = vec![45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 82, 83, 65, 32, 80, 82, 73, 86, 65, 84, 69, 32, 75, 69, 89, 45, 45, 45, 45, 45, 10, 77, 73, 73, 69, 111, 119, 73, 66, 65, 65, 75, 67, 65, 81, 69, 65, 55, 104, 84, 98, 54, 66, 82, 116, 48, 106, 105, 70, 81, 98, 66, 118, 57, 74, 115, 87, 82, 83, 112, 120, 71, 75, 47, 87, 88, 79, 112, 65, 81, 80, 102, 89, 107, 122, 104, 49, 115, 68, 105, 69, 103, 72, 121, 89, 10, 66, 117, 119, 119, 50, 81, 88, 50, 89, 85, 55, 47, 108, 71, 90, 107, 79, 73, 67, 111, 81, 66, 110, 106, 114, 102, 105, 57, 79, 103, 48, 119, 104, 106, 70, 52, 115, 118, 56, 110, 66, 52, 56, 84, 86, 65, 70, 71, 86, 70, 65, 90, 113, 66, 74, 84, 84, 77, 84, 113, 103, 65, 102, 90, 10, 99, 84, 114, 90, 87, 43, 49, 77, 103, 74, 119, 88, 57, 67, 72, 88, 84, 100, 110, 117, 80, 116, 111, 113, 56, 118, 113, 110, 80, 47, 81, 113, 121, 119, 65, 111, 110, 81, 101, 80, 85, 51, 80, 120, 99, 75, 76, 87, 51, 121, 87, 47, 97, 66, 74, 99, 69, 108, 107, 110, 114, 43, 53, 82, 10, 114, 113, 99, 74, 118, 75, 51, 110, 43, 66, 88, 77, 105, 72, 90, 56, 50, 109, 114, 75, 103, 72, 89, 48, 52, 83, 48, 70, 111, 43, 49, 48, 71, 107, 57, 98, 48, 113, 54, 83, 55, 87, 115, 84, 81, 73, 100, 113, 106, 98, 82, 120, 104, 105, 56, 53, 57, 97, 78, 71, 81, 71, 78, 79, 10, 52, 85, 78, 90, 77, 48, 75, 99, 75, 105, 51, 79, 99, 109, 90, 104, 53, 112, 106, 90, 52, 74, 101, 83, 43, 89, 83, 107, 111, 101, 69, 52, 86, 118, 87, 99, 55, 115, 74, 76, 98, 80, 83, 72, 57, 47, 90, 43, 97, 97, 53, 88, 85, 48, 100, 69, 88, 98, 52, 110, 43, 80, 72, 49, 10, 112, 99, 112, 90, 117, 53, 112, 103, 43, 90, 83, 109, 49, 107, 79, 89, 99, 82, 68, 51, 106, 53, 67, 85, 49, 90, 81, 51, 69, 75, 78, 74, 108, 78, 113, 111, 98, 119, 73, 68, 65, 81, 65, 66, 65, 111, 73, 66, 65, 65, 79, 100, 86, 51, 86, 102, 107, 103, 100, 71, 67, 109, 102, 106, 10, 54, 78, 56, 54, 49, 52, 121, 51, 82, 122, 53, 76, 116, 83, 74, 50, 65, 65, 71, 56, 103, 90, 74, 67, 111, 105, 55, 74, 118, 79, 70, 67, 103, 119, 66, 102, 53, 54, 72, 122, 52, 68, 105, 55, 47, 85, 57, 103, 101, 112, 99, 78, 66, 81, 68, 115, 73, 55, 80, 74, 101, 102, 51, 43, 10, 111, 48, 84, 50, 84, 86, 72, 83, 89, 43, 74, 79, 102, 115, 109, 103, 116, 49, 79, 105, 88, 55, 70, 89, 106, 101, 69, 49, 103, 67, 88, 118, 101, 74, 75, 113, 104, 82, 66, 76, 79, 119, 85, 99, 50, 90, 82, 65, 83, 48, 101, 73, 84, 111, 67, 118, 121, 85, 85, 108, 72, 120, 76, 117, 10, 102, 120, 80, 84, 55, 99, 110, 115, 105, 110, 87, 71, 53, 104, 121, 67, 114, 71, 90, 52, 54, 84, 52, 73, 81, 86, 79, 90, 57, 87, 119, 111, 120, 110, 47, 102, 120, 120, 82, 113, 83, 54, 90, 81, 75, 87, 49, 80, 70, 65, 113, 111, 97, 54, 85, 112, 70, 43, 55, 122, 106, 87, 77, 68, 10, 103, 53, 111, 74, 76, 81, 88, 56, 99, 76, 68, 66, 88, 79, 119, 78, 110, 52, 114, 76, 50, 79, 69, 90, 47, 104, 89, 89, 52, 65, 117, 90, 85, 103, 47, 82, 108, 77, 97, 109, 75, 87, 87, 67, 69, 108, 88, 76, 79, 100, 83, 73, 75, 57, 67, 77, 106, 112, 80, 78, 47, 116, 51, 76, 10, 120, 79, 115, 54, 107, 104, 109, 106, 71, 70, 103, 99, 71, 98, 103, 88, 114, 84, 53, 75, 52, 56, 110, 110, 104, 114, 72, 75, 102, 117, 108, 78, 69, 110, 113, 100, 56, 51, 104, 112, 122, 86, 82, 105, 104, 47, 83, 47, 86, 54, 65, 69, 78, 66, 85, 79, 75, 70, 102, 78, 112, 111, 67, 57, 10, 57, 85, 68, 118, 72, 104, 107, 67, 103, 89, 69, 65, 43, 73, 101, 48, 65, 119, 57, 76, 101, 82, 107, 76, 107, 55, 83, 43, 66, 69, 86, 81, 110, 52, 57, 121, 97, 72, 97, 86, 52, 73, 119, 122, 108, 68, 65, 97, 98, 121, 52, 104, 76, 51, 105, 50, 86, 108, 109, 111, 68, 75, 56, 84, 10, 72, 99, 43, 43, 115, 53, 86, 107, 89, 121, 76, 66, 110, 101, 84, 107, 52, 122, 76, 53, 83, 47, 73, 86, 101, 67, 85, 52, 71, 115, 43, 78, 121, 99, 70, 107, 120, 112, 99, 101, 77, 87, 87, 98, 117, 79, 109, 106, 102, 79, 99, 47, 82, 113, 115, 106, 53, 116, 89, 101, 75, 54, 74, 55, 10, 112, 85, 122, 54, 43, 109, 67, 113, 103, 70, 75, 53, 100, 119, 102, 101, 99, 84, 48, 48, 67, 106, 114, 77, 54, 51, 43, 116, 49, 113, 53, 49, 114, 79, 86, 99, 68, 115, 67, 53, 88, 56, 81, 122, 97, 47, 109, 77, 47, 108, 89, 57, 77, 69, 85, 67, 103, 89, 69, 65, 57, 84, 122, 67, 10, 102, 57, 113, 52, 77, 122, 72, 82, 73, 51, 113, 49, 80, 110, 52, 120, 110, 65, 75, 78, 121, 100, 85, 122, 74, 115, 102, 98, 81, 79, 47, 99, 111, 48, 85, 65, 88, 71, 119, 101, 74, 66, 87, 116, 102, 121, 68, 104, 80, 71, 122, 81, 104, 78, 89, 82, 83, 89, 122, 111, 48, 122, 80, 72, 10, 69, 65, 48, 81, 65, 109, 79, 114, 77, 119, 98, 108, 121, 107, 47, 98, 65, 98, 72, 119, 85, 101, 69, 116, 99, 118, 114, 118, 76, 105, 99, 53, 115, 70, 43, 105, 99, 80, 102, 116, 73, 74, 122, 108, 49, 52, 90, 68, 77, 66, 85, 48, 102, 47, 51, 97, 71, 109, 106, 104, 65, 85, 82, 119, 10, 43, 65, 75, 88, 85, 84, 88, 99, 116, 72, 97, 88, 118, 81, 116, 116, 70, 97, 88, 43, 100, 56, 114, 114, 98, 106, 73, 79, 73, 67, 97, 112, 117, 70, 121, 102, 81, 121, 77, 67, 103, 89, 65, 70, 51, 115, 54, 49, 115, 56, 114, 73, 108, 88, 114, 99, 104, 107, 120, 109, 116, 87, 120, 117, 10, 71, 71, 108, 80, 90, 108, 50, 114, 55, 67, 80, 98, 119, 68, 99, 102, 111, 83, 116, 80, 102, 55, 53, 117, 48, 55, 100, 81, 100, 87, 73, 121, 78, 104, 72, 47, 69, 43, 120, 72, 71, 121, 56, 80, 108, 55, 83, 65, 87, 86, 102, 105, 72, 49, 109, 54, 101, 77, 97, 87, 101, 52, 105, 82, 10, 49, 50, 117, 86, 57, 85, 80, 86, 84, 116, 48, 97, 120, 81, 111, 68, 106, 85, 76, 70, 88, 73, 50, 65, 105, 108, 89, 48, 71, 97, 90, 113, 66, 83, 78, 52, 102, 111, 103, 73, 100, 43, 118, 66, 107, 65, 73, 70, 69, 114, 107, 68, 57, 78, 101, 97, 83, 71, 51, 71, 119, 71, 65, 118, 10, 77, 85, 117, 51, 88, 88, 52, 68, 99, 82, 76, 49, 51, 102, 77, 105, 110, 115, 55, 98, 77, 81, 75, 66, 103, 72, 70, 69, 57, 82, 107, 85, 114, 115, 117, 71, 107, 80, 66, 119, 78, 116, 74, 56, 101, 118, 70, 121, 66, 73, 100, 97, 110, 57, 117, 106, 112, 57, 78, 103, 100, 109, 111, 54, 10, 55, 113, 88, 66, 107, 108, 74, 99, 97, 78, 119, 49, 70, 90, 78, 82, 78, 121, 97, 68, 115, 85, 120, 108, 100, 119, 120, 70, 43, 65, 87, 106, 52, 117, 99, 88, 110, 102, 86, 100, 108, 68, 108, 84, 108, 80, 89, 57, 100, 54, 66, 53, 47, 119, 73, 67, 103, 81, 75, 121, 80, 50, 85, 70, 10, 90, 119, 81, 67, 110, 49, 88, 87, 52, 104, 111, 102, 43, 49, 120, 48, 68, 117, 71, 110, 73, 70, 118, 101, 89, 84, 54, 121, 109, 47, 77, 82, 84, 48, 55, 70, 77, 65, 70, 121, 88, 84, 101, 70, 49, 89, 97, 81, 79, 117, 54, 100, 110, 81, 119, 121, 116, 109, 43, 72, 76, 66, 68, 112, 10, 82, 117, 52, 57, 65, 111, 71, 66, 65, 75, 56, 53, 54, 111, 73, 98, 90, 86, 104, 71, 54, 117, 52, 70, 90, 87, 114, 68, 79, 67, 69, 75, 106, 86, 121, 122, 67, 100, 110, 69, 54, 120, 57, 84, 90, 49, 97, 79, 99, 88, 115, 88, 102, 76, 50, 67, 105, 69, 84, 75, 78, 76, 75, 98, 10, 100, 67, 77, 115, 119, 112, 108, 76, 56, 43, 119, 83, 82, 114, 57, 122, 67, 113, 101, 103, 67, 121, 77, 52, 74, 83, 103, 72, 81, 65, 83, 49, 51, 107, 79, 89, 106, 70, 102, 52, 99, 115, 70, 74, 67, 103, 69, 76, 55, 47, 51, 56, 122, 84, 106, 120, 86, 105, 110, 111, 84, 82, 77, 43, 10, 116, 101, 86, 83, 56, 105, 99, 82, 82, 57, 106, 54, 51, 106, 116, 81, 107, 105, 118, 116, 50, 105, 122, 86, 107, 106, 110, 88, 65, 84, 73, 83, 100, 48, 71, 97, 100, 49, 78, 121, 77, 116, 98, 53, 56, 79, 86, 74, 65, 55, 48, 53, 10, 45, 45, 45, 45, 45, 69, 78, 68, 32, 82, 83, 65, 32, 80, 82, 73, 86, 65, 84, 69, 32, 75, 69, 89, 45, 45, 45, 45, 45, 10];
    Rsa::private_key_from_pem(&private_key_pem).unwrap()
}