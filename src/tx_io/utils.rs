use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, AeadCore, KeyInit},
    Aes256Gcm, Key,
};
use alloy_rlp::{Decodable, Encodable};
use hkdf::Hkdf;
use secp256k1::{ecdh::SharedSecret, PublicKey, SecretKey};
use sha2::Sha256;
use serde::{Deserialize, Serialize};
use serde_json;
use std::fs::File;
use std::io::{self, BufReader};


#[derive(Serialize, Deserialize)]
pub struct Secp256k1KeyPair {
    pub secret_key: SecretKey,
    pub public_key: PublicKey,
}

// converts a u64 nonce to a GenericArray<u8, N> where N is the size of the nonce
fn u64_to_generic_u8_array(nonce: u64) -> GenericArray<u8, <Aes256Gcm as AeadCore>::NonceSize> {
    let mut nonce_bytes = nonce.to_be_bytes().to_vec();
    let crypto_nonce_size = GenericArray::<u8, <Aes256Gcm as AeadCore>::NonceSize>::default().len();
    nonce_bytes.resize(crypto_nonce_size, 0); // pad for crypto
    GenericArray::clone_from_slice(&nonce_bytes)
}

// encrypts a plaintext using the given key and nonce
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

// decrypts a ciphertext using the given key and nonce
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

// derives a aes key from a shared secret
pub fn derive_aes_key(shared_secret: &SharedSecret) -> Result<Key<Aes256Gcm>, hkdf::InvalidLength> {
    // Initialize HKDF with SHA-256
    let hk = Hkdf::<Sha256>::new(None, &shared_secret.secret_bytes());

    // Output a 32-byte key for AES-256
    let mut okm = [0u8; 32];
    hk.expand(b"aes-gcm key", &mut okm)?;
    Ok(*Key::<Aes256Gcm>::from_slice(&okm))
}

// reads a secp256k1 keypair from a file
pub fn read_secp256k1_keypair(path: &str) -> io::Result<Secp256k1KeyPair> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    serde_json::from_reader(reader).map_err(|e| io::Error::new(io::ErrorKind::Other, e))
}
