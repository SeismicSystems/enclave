use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, AeadCore, KeyInit},
    Aes256Gcm, Key,
};
use alloy_rlp::{Decodable, Encodable};
use hkdf::Hkdf;
use secp256k1::{ecdh::SharedSecret, PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use serde_json;
use sha2::Sha256;
use std::fs::File;
use std::io::{self, BufReader};

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
fn u64_to_generic_u8_array(nonce: u64) -> GenericArray<u8, <Aes256Gcm as AeadCore>::NonceSize> {
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
pub fn aes_decrypt<T>(key: &Key<Aes256Gcm>, ciphertext: &[u8], nonce: u64) -> T
where
    T: Decodable,
{
    let cipher = Aes256Gcm::new(key);
    let nonce = u64_to_generic_u8_array(nonce);

    // recover the plaintext byte encoding of the object
    let buf = cipher
        .decrypt(&nonce, ciphertext.as_ref())
        .expect("AES decryption failed");

    // recover the object from the byte encoding
    T::decode(&mut &buf[..]).unwrap_or_else(|err| panic!("Failed to decode: {:?}", err))
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

/// Reads a secp256k1 keypair from a JSON file.
///
/// This function reads a secp256k1 keypair from a file in JSON format.
/// It returns a `Secp256k1KeyPair` containing the public and private keys.
///
/// # Arguments
/// * `path` - The file path to the keypair JSON file.
///
/// # Returns
/// A `Result` containing the `Secp256k1KeyPair`, or an I/O error if the file could not be read or parsed.
pub fn read_secp256k1_keypair(path: &str) -> io::Result<Secp256k1KeyPair> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    serde_json::from_reader(reader).map_err(|e| io::Error::new(io::ErrorKind::Other, e))
}
