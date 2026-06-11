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
//! The authoritative node-side parser is
//! `enclave/crates/seismic-attestation/src/manifest.rs`; this schema mirror
//! must stay in lockstep with it (both pin the same fixture vector).

use crate::error::{Result, TdxInitError};
use base64::Engine;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tracing::info;

/// The manifest schema version this validator implements.
pub const MANIFEST_VERSION: u64 = 1;

/// Strict v1 schema. Unknown keys are rejected so two verifiers can never
/// disagree on field semantics; hex shapes are validated in
/// [`validate_manifest_bytes`]. Deserialize-only: tdx-init must never emit
/// manifest bytes.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkManifestV1 {
    manifest_version: u64,
    name: String,
    genesis_nonce: String,
    eth: EthManifest,
    summit: SummitManifest,
    measurements: MeasurementsManifest,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EthManifest {
    chain_id: u64,
    genesis_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SummitManifest {
    genesis_template_hash: String,
    namespace: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MeasurementsManifest {
    bootstrap_policy_hash: String,
    contracts: ContractsManifest,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContractsManifest {
    registry: String,
    authority: String,
}

/// Decode the `[network].manifest_base64` embed and strictly validate it.
/// Returns the exact manifest bytes to write (and hash) — callers must not
/// transform them further.
pub fn decode_and_validate(manifest_base64: &str) -> Result<Vec<u8>> {
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
    validate_manifest_bytes(&bytes)?;
    Ok(bytes)
}

/// `network_id` presentation form: lowercase 0x-hex of SHA-256(bytes).
/// Equivalently `sha256sum` of the written file — every mismatch diagnosis
/// starts with comparing this line against the deploy tool's output.
pub fn network_id_hex(manifest_bytes: &[u8]) -> String {
    let digest = Sha256::digest(manifest_bytes);
    let mut out = String::with_capacity(2 + 64);
    out.push_str("0x");
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn validate_manifest_bytes(bytes: &[u8]) -> Result<()> {
    // Probe the version before the strict parse: a future-version manifest
    // carries fields this schema doesn't know, and "unsupported
    // manifest_version 2" is the actionable error, not "unknown field".
    #[derive(Deserialize)]
    struct VersionProbe {
        manifest_version: u64,
    }
    let probe: VersionProbe = serde_json::from_slice(bytes)
        .map_err(|e| TdxInitError::InvalidManifest(format!("not a manifest JSON object: {e}")))?;
    if probe.manifest_version != MANIFEST_VERSION {
        return Err(TdxInitError::InvalidManifest(format!(
            "unsupported manifest_version {}; this validator implements v{}",
            probe.manifest_version, MANIFEST_VERSION
        )));
    }

    let manifest: NetworkManifestV1 = serde_json::from_slice(bytes).map_err(|e| {
        TdxInitError::InvalidManifest(format!("does not match schema v{MANIFEST_VERSION}: {e}"))
    })?;
    check_hex(&manifest.genesis_nonce, 32, "genesis_nonce")?;
    check_hex(&manifest.eth.genesis_hash, 32, "eth.genesis_hash")?;
    check_hex(
        &manifest.summit.genesis_template_hash,
        32,
        "summit.genesis_template_hash",
    )?;
    check_hex(
        &manifest.measurements.bootstrap_policy_hash,
        32,
        "measurements.bootstrap_policy_hash",
    )?;
    check_hex(
        &manifest.measurements.contracts.registry,
        20,
        "measurements.contracts.registry",
    )?;
    check_hex(
        &manifest.measurements.contracts.authority,
        20,
        "measurements.contracts.authority",
    )?;

    info!(
        "network manifest valid (v{}): name={} chain_id={} namespace={} network_id={}",
        manifest.manifest_version,
        manifest.name,
        manifest.eth.chain_id,
        manifest.summit.namespace,
        network_id_hex(bytes),
    );
    Ok(())
}

fn check_hex(value: &str, nbytes: usize, field: &str) -> Result<()> {
    let err = || {
        TdxInitError::InvalidManifest(format!(
            "{field}: expected 0x-prefixed {nbytes}-byte hex string, got {value:?}"
        ))
    };
    let digits = value.strip_prefix("0x").ok_or_else(err)?;
    if digits.len() != 2 * nbytes || !digits.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(err());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// seismic-attestation's fixture, included directly so this mirror can
    /// never drift from the authoritative parser unnoticed; the network_id
    /// vector below is asserted by that crate (and by the deploy tool's
    /// tests), pinning all stacks to the same bytes.
    const FIXTURE: &[u8] =
        include_bytes!("../../seismic-attestation/fixtures/network-manifest-v1.json");
    const FIXTURE_NETWORK_ID: &str =
        "0xc4d4721b2e287df26022e6d27c8cf772841a872b6be08b1938cbc76d88703747";

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    #[test]
    fn decodes_and_validates_fixture() {
        let bytes = decode_and_validate(&b64(FIXTURE)).unwrap();
        assert_eq!(bytes, FIXTURE, "decoded bytes must be verbatim");
        assert_eq!(network_id_hex(&bytes), FIXTURE_NETWORK_ID);
    }

    #[test]
    fn tolerates_wrapped_base64_without_changing_bytes() {
        let mut wrapped = b64(FIXTURE);
        wrapped.insert(10, '\n');
        wrapped.insert(40, ' ');
        let bytes = decode_and_validate(&wrapped).unwrap();
        assert_eq!(bytes, FIXTURE);
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

    #[test]
    fn rejects_unknown_fields() {
        let mut value: serde_json::Value = serde_json::from_slice(FIXTURE).unwrap();
        value["tx_io_pk"] = "0x02ab".into();
        let bytes = serde_json::to_vec(&value).unwrap();
        let err = decode_and_validate(&b64(&bytes)).unwrap_err();
        assert!(err.to_string().contains("unknown field"), "{err}");
    }

    #[test]
    fn reports_unsupported_version_before_unknown_fields() {
        let mut value: serde_json::Value = serde_json::from_slice(FIXTURE).unwrap();
        value["manifest_version"] = 2.into();
        value["some_v2_field"] = "new".into();
        let bytes = serde_json::to_vec(&value).unwrap();
        let err = decode_and_validate(&b64(&bytes)).unwrap_err();
        assert!(
            err.to_string().contains("unsupported manifest_version 2"),
            "{err}"
        );
    }

    #[test]
    fn rejects_malformed_hex_fields() {
        let fixture = || -> serde_json::Value { serde_json::from_slice(FIXTURE).unwrap() };

        // wrong length for a 32-byte field
        let mut wrong_length = fixture();
        wrong_length["genesis_nonce"] = format!("0x{}", "aa".repeat(31)).into();
        // missing 0x prefix
        let mut missing_prefix = fixture();
        missing_prefix["eth"]["genesis_hash"] = "ab".repeat(32).into();
        // non-hex digits
        let mut non_hex = fixture();
        non_hex["measurements"]["bootstrap_policy_hash"] = format!("0x{}", "zz".repeat(32)).into();

        for (field, value) in [
            ("genesis_nonce", wrong_length),
            ("eth.genesis_hash", missing_prefix),
            ("measurements.bootstrap_policy_hash", non_hex),
        ] {
            let bytes = serde_json::to_vec(&value).unwrap();
            assert!(
                decode_and_validate(&b64(&bytes)).is_err(),
                "expected rejection for field {field}"
            );
        }
    }
}
