//! EIP-712 typed-data digest for council delivery signatures.
//!
//! The council signs with an ordinary Ethereum wallet, so the signed digest
//! is EIP-712 typed data (keccak-256) — a wallet can display "authorize the
//! root key for epoch 3 on network X" instead of an opaque hash. The
//! network id rides in the domain separator as `salt`, so a signature can
//! never migrate across networks; the key itself appears only as its
//! keccak-256 **commitment**, so the secret never passes through wallet UIs
//! or extension logs while the signature still binds the exact bytes.
//!
//! [`typed_data_json`] emits the eth_signTypedData_v4 JSON for exactly the
//! digest [`payload_digest`] computes; council tooling hands it to MetaMask,
//! `cast wallet sign --data`, or a hardware wallet, and attaches the 65-byte
//! `r || s || v` signature to the envelope.

use crate::messages::DeliveryPayload;
use alloy_primitives::keccak256;

/// EIP-712 domain: `name`, `version`, and the network id as `salt` (no
/// chainId — deliveries are not on-chain transactions, and the network id is
/// the stronger scope).
const DOMAIN_TYPE: &str = "EIP712Domain(string name,string version,bytes32 salt)";
pub const DOMAIN_NAME: &str = "SeismicCouncilKeyDelivery";
pub const DOMAIN_VERSION: &str = "1";

/// The one signed struct: the epoch being rotated to, and the commitment to
/// the 32-byte root key every purpose key of that epoch derives from.
const KEY_DELIVERY_TYPE: &str = "RootKeyDelivery(uint64 epoch,bytes32 keyCommitment)";

/// keccak-256 of the 32-byte epoch root key — what the wallet signs in place
/// of the key itself.
pub fn key_commitment(key: &[u8; 32]) -> [u8; 32] {
    keccak256(key).0
}

fn domain_separator(network_id: &[u8; 32]) -> [u8; 32] {
    let mut words = Vec::with_capacity(4 * 32);
    words.extend_from_slice(keccak256(DOMAIN_TYPE).as_slice());
    words.extend_from_slice(keccak256(DOMAIN_NAME).as_slice());
    words.extend_from_slice(keccak256(DOMAIN_VERSION).as_slice());
    words.extend_from_slice(network_id);
    keccak256(&words).0
}

fn struct_hash(payload: &DeliveryPayload) -> [u8; 32] {
    let mut epoch_word = [0u8; 32];
    epoch_word[24..].copy_from_slice(&payload.epoch.to_be_bytes());

    let mut words = Vec::with_capacity(3 * 32);
    words.extend_from_slice(keccak256(KEY_DELIVERY_TYPE).as_slice());
    words.extend_from_slice(&epoch_word);
    words.extend_from_slice(&key_commitment(&payload.key));
    keccak256(&words).0
}

/// The 32-byte digest the council wallet signs:
/// `keccak256(0x1901 || domainSeparator || structHash)`.
pub fn payload_digest(payload: &DeliveryPayload) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(2 + 2 * 32);
    preimage.extend_from_slice(&[0x19, 0x01]);
    preimage.extend_from_slice(&domain_separator(&payload.network_id));
    preimage.extend_from_slice(&struct_hash(payload));
    keccak256(&preimage).0
}

/// The `eth_signTypedData_v4` JSON for `payload` — hand this to a wallet
/// (MetaMask, `cast wallet sign --data`, hardware wallets) and it produces
/// a signature over exactly [`payload_digest`]. Contains the key's
/// commitment, never the key.
pub fn typed_data_json(payload: &DeliveryPayload) -> String {
    format!(
        concat!(
            r#"{{"types":{{"#,
            r#""EIP712Domain":[{{"name":"name","type":"string"}},"#,
            r#"{{"name":"version","type":"string"}},"#,
            r#"{{"name":"salt","type":"bytes32"}}],"#,
            r#""RootKeyDelivery":[{{"name":"epoch","type":"uint64"}},"#,
            r#"{{"name":"keyCommitment","type":"bytes32"}}]}},"#,
            r#""primaryType":"RootKeyDelivery","#,
            r#""domain":{{"name":"{name}","version":"{version}","salt":"0x{salt}"}},"#,
            r#""message":{{"epoch":{epoch},"#,
            r#""keyCommitment":"0x{commitment}"}}}}"#,
        ),
        name = DOMAIN_NAME,
        version = DOMAIN_VERSION,
        salt = hex::encode(payload.network_id),
        epoch = payload.epoch,
        commitment = hex::encode(key_commitment(&payload.key)),
    )
}

/// The Ethereum address of a secp256k1 public key:
/// `keccak256(uncompressed[1..])[12..]`. Used to check a recovered signer
/// against the configured council address, and by tooling/tests to derive
/// the address to configure.
pub fn address_from_pubkey(pk: &secp256k1::PublicKey) -> [u8; 20] {
    let uncompressed = pk.serialize_uncompressed();
    keccak256(&uncompressed[1..])[12..]
        .try_into()
        .expect("keccak256 output has 32 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> DeliveryPayload {
        DeliveryPayload {
            network_id: [0x11; 32],
            epoch: 7,
            key: [0x44; 32],
        }
    }

    /// Golden vector: signatures over this digest live on disk and in
    /// council custody; it must never change. Independently reproducible
    /// with foundry: `cast keccak $(cast abi-encode ...)` per EIP-712, or
    /// `cast wallet sign --data '<typed_data_json(payload)>'`.
    #[test]
    fn digest_matches_golden_vector() {
        assert_eq!(
            hex::encode(payload_digest(&fixture())),
            "552c6a04685ba82eb0a71e390e598fabb8799d807978e6fb8bfbe83b5002b967"
        );
    }

    /// Every field perturbs the digest.
    #[test]
    fn digest_is_sensitive_to_every_field() {
        let base = payload_digest(&fixture());
        let mut variants = Vec::new();
        for mutate in [
            (|p: &mut DeliveryPayload| p.network_id = [0x12; 32]) as fn(&mut DeliveryPayload),
            |p| p.epoch = 8,
            |p| p.key = [0x45; 32],
        ] {
            let mut payload = fixture();
            mutate(&mut payload);
            variants.push(payload_digest(&payload));
        }
        for (i, variant) in variants.iter().enumerate() {
            assert_ne!(&base, variant, "variant {i} must change the digest");
        }
    }

    #[test]
    fn typed_data_json_is_wallet_shaped_and_key_free() {
        let json = typed_data_json(&fixture());
        assert!(json.contains(r#""primaryType":"RootKeyDelivery""#));
        assert!(json.contains(r#""epoch":7"#));
        assert!(json.contains(&format!("0x{}", hex::encode([0x11u8; 32]))));
        // The commitment appears; the key itself never does.
        assert!(json.contains(&format!("0x{}", hex::encode(key_commitment(&[0x44; 32])))));
        assert!(!json.contains(&hex::encode([0x44u8; 32])));
        serde_json::from_str::<serde_json::Value>(&json).expect("valid JSON");
    }

    #[test]
    fn address_matches_known_ethereum_derivation() {
        // Private key 0x...01 has the well-known address
        // 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf.
        let sk = secp256k1::SecretKey::from_byte_array(&{
            let mut k = [0u8; 32];
            k[31] = 1;
            k
        })
        .unwrap();
        let pk = secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &sk);
        assert_eq!(
            hex::encode(address_from_pubkey(&pk)),
            "7e5f4552091a69125d5dfcb7b8c2659029395bdf"
        );
    }
}
