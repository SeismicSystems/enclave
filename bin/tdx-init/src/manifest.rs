//! Network-manifest validation at POST time.
//!
//! The manifest defines a network's identity: `network_id = SHA-256(exact
//! file bytes)`. It travels as opaque bytes through every hop: tdx-init
//! decodes the base64 embed from `[network]`,
//! validates it strictly so a bad manifest fails the deploy POST rather than
//! a later boot, and writes the decoded bytes verbatim to
//! `network-manifest.json` under [`crate::CONF_DIR`] — never
//! parse-and-re-serialize, since any re-rendering risks changing the bytes
//! and therefore the `network_id`.
//!
//! The schema and `network_id` derivation live in `seismic-network-manifest`,
//! shared with the node-side parser (`seismic-attestation`).

use crate::error::{Result, TdxInitError};
use base64::Engine;
use seismic_network_manifest::{NetworkId, NetworkManifestV1};
use tracing::info;

/// A manifest that passed strict validation: the exact bytes to write (and
/// hash) — callers must not transform them further — plus the fields other
/// POST-time checks cross-reference, so they never re-parse the schema.
#[derive(Debug)]
pub struct ValidatedManifest {
    pub bytes: Vec<u8>,
    pub chain_id: u64,
}

/// Decode the `[network].manifest_base64` embed and strictly validate it.
pub fn decode_and_validate(manifest_base64: &str) -> Result<ValidatedManifest> {
    // Be forgiving about transport-layer line wrapping (PEM-style); this
    // changes nothing about the decoded bytes.
    let stripped: String = manifest_base64
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(stripped)
        .map_err(|e| {
            TdxInitError::InvalidManifest(format!("manifest_base64 is not valid base64: {e}"))
        })?;
    let manifest = NetworkManifestV1::from_json_bytes(&bytes)
        .map_err(|e| TdxInitError::InvalidManifest(e.to_string()))?;

    info!(
        "network manifest valid (v{}): name={} chain_id={} namespace={} network_id={}",
        manifest.manifest_version,
        manifest.name,
        manifest.eth.chain_id,
        manifest.summit.namespace,
        network_id_hex(&bytes),
    );
    Ok(ValidatedManifest {
        bytes,
        chain_id: manifest.eth.chain_id,
    })
}

/// `network_id` presentation form: lowercase 0x-hex of SHA-256(bytes).
/// Equivalently `sha256sum` of the written file — every mismatch diagnosis
/// starts with comparing this line against the deploy tool's output.
pub fn network_id_hex(manifest_bytes: &[u8]) -> String {
    NetworkId::from_manifest_bytes(manifest_bytes).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The schema crate's golden fixture; the network_id vector below is
    /// asserted by that crate (and by the deploy tool's tests), pinning all
    /// stacks to the same bytes.
    const FIXTURE: &[u8] =
        include_bytes!("../../../crates/network-manifest/fixtures/network-manifest-v1.json");
    const FIXTURE_NETWORK_ID: &str =
        "0xc4d4721b2e287df26022e6d27c8cf772841a872b6be08b1938cbc76d88703747";

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    #[test]
    fn decodes_and_validates_fixture() {
        let manifest = decode_and_validate(&b64(FIXTURE)).unwrap();
        assert_eq!(manifest.bytes, FIXTURE, "decoded bytes must be verbatim");
        assert_eq!(network_id_hex(&manifest.bytes), FIXTURE_NETWORK_ID);
        assert_eq!(manifest.chain_id, 5124);
    }

    #[test]
    fn tolerates_wrapped_base64_without_changing_bytes() {
        let mut wrapped = b64(FIXTURE);
        wrapped.insert(10, '\n');
        wrapped.insert(40, ' ');
        let manifest = decode_and_validate(&wrapped).unwrap();
        assert_eq!(manifest.bytes, FIXTURE);
    }

    // Byte-exactness: a cosmetic edit still parses but is a different network.
    #[test]
    fn network_id_is_over_raw_bytes() {
        let mut edited = FIXTURE.to_vec();
        edited.push(b'\n');
        decode_and_validate(&b64(&edited)).unwrap();
        assert_ne!(network_id_hex(&edited), FIXTURE_NETWORK_ID);
    }

    #[test]
    fn rejects_invalid_base64() {
        let err = decode_and_validate("not-base64!!!").unwrap_err();
        assert!(err.to_string().contains("base64"), "{err}");
    }

    // Schema enforcement (unknown fields, version probe, hex shapes) is the
    // schema crate's job, tested there; this only pins that its errors
    // surface as InvalidManifest POST failures.
    #[test]
    fn maps_schema_errors_to_invalid_manifest() {
        let mut value: serde_json::Value = serde_json::from_slice(FIXTURE).unwrap();
        value["tx_io_pk"] = "0x02ab".into();
        let bytes = serde_json::to_vec(&value).unwrap();
        let err = decode_and_validate(&b64(&bytes)).unwrap_err();
        assert!(err.to_string().contains("unknown field"), "{err}");
    }
}
