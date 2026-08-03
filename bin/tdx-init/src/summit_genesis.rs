//! summit-genesis validation at POST time.
//!
//! The summit genesis TOML is the consensus-layer genesis every node's summit
//! boots from (`--genesis-path /run/seismic/conf/summit-genesis.toml`). Unlike
//! a template, it is complete at delivery: the founding ceremony harvests the
//! validator set into it before the config POST, so it is identical on every
//! node of a network and re-POSTed verbatim on every boot, exactly like
//! `reth-genesis.json`.
//!
//! The manifest's `summit.genesis_config_digest` pins the file — but tdx-init
//! deliberately does *not* recompute it. That digest is SHA-256 over summit's
//! own domain-prefixed SSZ serialization, so recomputing it in-process here
//! would mean reimplementing summit's SSZ layout, and a divergence between the two
//! implementations would reject valid deployments. It isn't needed either:
//! deploy verifies the digest against the manifest pin before POSTing, and
//! summit derives its P2P and signing domains from
//! `chain_domain(config_digest)`, so a node fed a divergent genesis cannot
//! complete a handshake with the cohort. POST-time validation here is
//! structural, exactly like the reth half (which cannot recompute
//! `keccak(rlp(header))` either): valid TOML whose `namespace` matches the
//! manifest's `summit.namespace`.
//!
//! Like the manifest, the file travels base64-encoded and is written
//! verbatim — summit parses it itself, so tdx-init must not re-render it.

use crate::error::{Result, TdxInitError};
use base64::Engine;
use serde::Deserialize;
use tracing::info;

/// Minimal probe: only the cross-checked field is parsed. The genesis
/// schema belongs to summit — it is not re-validated here.
#[derive(Deserialize)]
struct GenesisProbe {
    namespace: String,
}

/// Decode the `[network].summit_genesis_base64` embed and validate it against
/// the validated manifest's `summit.namespace`. Returns the exact genesis bytes
/// to write — callers must not transform them further.
///
/// Deliberately unchecked: `summit.genesis_config_digest`. Verifying it here is
/// possible — shell out to the summit binary, or link its SSZ serialization —
/// but both add a dependency this boot-time translator doesn't otherwise carry
/// (the image's binary layout, or summit's crates). The module docs cover why
/// the structural check suffices.
pub fn decode_and_validate(
    summit_genesis_base64: &str,
    manifest_namespace: &str,
) -> Result<Vec<u8>> {
    // Be forgiving about transport-layer line wrapping (PEM-style); this
    // changes nothing about the decoded bytes.
    let stripped: String = summit_genesis_base64
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(stripped)
        .map_err(|e| {
            TdxInitError::InvalidSummitGenesis(format!(
                "summit_genesis_base64 is not valid base64: {e}"
            ))
        })?;

    let text = std::str::from_utf8(&bytes).map_err(|e| {
        TdxInitError::InvalidSummitGenesis(format!(
            "not a summit genesis TOML document: bytes are not valid UTF-8: {e}"
        ))
    })?;
    let genesis: GenesisProbe = toml::from_str(text).map_err(|e| {
        TdxInitError::InvalidSummitGenesis(format!(
            "not a summit genesis TOML document with a string namespace: {e}"
        ))
    })?;
    if genesis.namespace != manifest_namespace {
        return Err(TdxInitError::InvalidSummitGenesis(format!(
            "namespace {:?} does not match the manifest's summit.namespace {:?}",
            genesis.namespace, manifest_namespace
        )));
    }

    info!(
        "summit genesis valid: namespace={} ({} bytes)",
        genesis.namespace,
        bytes.len(),
    );
    Ok(bytes)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Namespace matching the shared manifest fixture's `summit.namespace`.
    pub(crate) const FIXTURE_NAMESPACE: &str = "seismic-devnet-3";

    pub(crate) fn genesis_toml(namespace: &str) -> Vec<u8> {
        format!(
            "namespace = \"{namespace}\"\nchain_id = 5124\n\n[[validators]]\nbls_pubkey = \"0xab\"\n"
        )
        .into_bytes()
    }

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    #[test]
    fn decodes_and_validates_matching_namespace() {
        let raw = genesis_toml(FIXTURE_NAMESPACE);
        let bytes = decode_and_validate(&b64(&raw), FIXTURE_NAMESPACE).unwrap();
        assert_eq!(bytes, raw, "decoded bytes must be verbatim");
    }

    #[test]
    fn tolerates_wrapped_base64_without_changing_bytes() {
        let raw = genesis_toml(FIXTURE_NAMESPACE);
        let mut wrapped = b64(&raw);
        wrapped.insert(10, '\n');
        wrapped.insert(20, ' ');
        let bytes = decode_and_validate(&wrapped, FIXTURE_NAMESPACE).unwrap();
        assert_eq!(bytes, raw);
    }

    #[test]
    fn rejects_invalid_base64() {
        let err = decode_and_validate("not-base64!!!", FIXTURE_NAMESPACE).unwrap_err();
        assert!(err.to_string().contains("base64"), "{err}");
    }

    #[test]
    fn rejects_non_toml_bytes() {
        let err =
            decode_and_validate(&b64(b"{\"namespace\": \"x\""), FIXTURE_NAMESPACE).unwrap_err();
        assert!(err.to_string().contains("summit genesis TOML"), "{err}");
    }

    #[test]
    fn rejects_toml_without_namespace() {
        let err = decode_and_validate(&b64(b"chain_id = 5124\n"), FIXTURE_NAMESPACE).unwrap_err();
        assert!(err.to_string().contains("namespace"), "{err}");
    }

    #[test]
    fn rejects_namespace_mismatch() {
        let raw = genesis_toml("seismic-devnet-4");
        let err = decode_and_validate(&b64(&raw), FIXTURE_NAMESPACE).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("seismic-devnet-4") && msg.contains("seismic-devnet-3"),
            "{msg}"
        );
    }
}
