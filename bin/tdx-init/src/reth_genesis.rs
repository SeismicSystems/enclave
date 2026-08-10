//! reth-genesis validation at POST time.
//!
//! The reth genesis JSON is the chain spec every node's reth boots from
//! (`--chain /run/seismic/conf/reth-genesis.json`). It is fully
//! deploy-time-computable (no TEE-born data) and identical on every node of a
//! network. The manifest's `eth.genesis_hash = keccak(rlp(header))` pins the
//! file's genesis *block* — the header and, through the state root, the
//! alloc — but not its `config` section (fork schedule), which lies outside
//! the header. tdx-init also does not recompute that hash in-process (it
//! would need reth's own chain-spec parse path), so POST-time validation here is
//! structural: valid JSON whose `config.chainId` matches the manifest's
//! `eth.chain_id`. The block-hash commitment is enforced outside the node:
//! the deploy tooling recomputes the hash with reth's own implementation
//! when it assembles the manifest, and checks at launch that every node's
//! reth serves the pinned hash as block 0.
//!
//! Like the manifest, the file travels base64-encoded and is written
//! verbatim — reth parses it itself, so tdx-init must not re-render it.

use crate::error::{Result, TdxInitError};
use base64::Engine;
use serde::Deserialize;
use tracing::info;

/// Minimal probe: only the cross-checked field is parsed. The genesis
/// schema belongs to reth — it is not re-validated here.
#[derive(Deserialize)]
struct GenesisProbe {
    config: GenesisConfigProbe,
}

#[derive(Deserialize)]
struct GenesisConfigProbe {
    #[serde(rename = "chainId")]
    chain_id: u64,
}

/// Decode the `[network].reth_genesis_base64` embed and validate it against
/// the validated manifest's `eth.chain_id`. Returns the exact genesis bytes
/// to write — callers must not transform them further.
///
/// Deliberately unchecked: `eth.genesis_hash`. Verifying it here is possible —
/// shell out to `seismic-reth genesis-hash`, or link reth's chain-spec stack —
/// but both add a dependency this boot-time translator doesn't otherwise carry
/// (the image's binary layout, or reth's crates). The module docs cover why the
/// structural check suffices.
pub fn decode_and_validate(reth_genesis_base64: &str, manifest_chain_id: u64) -> Result<Vec<u8>> {
    // Be forgiving about transport-layer line wrapping (PEM-style); this
    // changes nothing about the decoded bytes.
    let stripped: String = reth_genesis_base64
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(stripped)
        .map_err(|e| {
            TdxInitError::InvalidRethGenesis(format!(
                "reth_genesis_base64 is not valid base64: {e}"
            ))
        })?;

    let genesis: GenesisProbe = serde_json::from_slice(&bytes).map_err(|e| {
        TdxInitError::InvalidRethGenesis(format!(
            "not a genesis JSON object with integer config.chainId: {e}"
        ))
    })?;
    if genesis.config.chain_id != manifest_chain_id {
        return Err(TdxInitError::InvalidRethGenesis(format!(
            "config.chainId {} does not match the manifest's eth.chain_id {}",
            genesis.config.chain_id, manifest_chain_id
        )));
    }

    info!(
        "reth genesis valid: chainId={} ({} bytes)",
        genesis.config.chain_id,
        bytes.len(),
    );
    Ok(bytes)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Chain id matching the shared manifest fixture's `eth.chain_id`.
    pub(crate) const FIXTURE_CHAIN_ID: u64 = 5124;

    pub(crate) fn genesis_json(chain_id: u64) -> Vec<u8> {
        format!(
            r#"{{"config":{{"chainId":{chain_id},"mercuryTime":0}},"alloc":{{}},"gasLimit":"0x1c9c380"}}"#
        )
        .into_bytes()
    }

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    #[test]
    fn decodes_and_validates_matching_chain_id() {
        let raw = genesis_json(FIXTURE_CHAIN_ID);
        let bytes = decode_and_validate(&b64(&raw), FIXTURE_CHAIN_ID).unwrap();
        assert_eq!(bytes, raw, "decoded bytes must be verbatim");
    }

    #[test]
    fn tolerates_wrapped_base64_without_changing_bytes() {
        let raw = genesis_json(FIXTURE_CHAIN_ID);
        let mut wrapped = b64(&raw);
        wrapped.insert(10, '\n');
        wrapped.insert(20, ' ');
        let bytes = decode_and_validate(&wrapped, FIXTURE_CHAIN_ID).unwrap();
        assert_eq!(bytes, raw);
    }

    #[test]
    fn rejects_invalid_base64() {
        let err = decode_and_validate("not-base64!!!", FIXTURE_CHAIN_ID).unwrap_err();
        assert!(err.to_string().contains("base64"), "{err}");
    }

    #[test]
    fn rejects_non_genesis_json() {
        let err = decode_and_validate(&b64(b"{\"alloc\":{}}"), FIXTURE_CHAIN_ID).unwrap_err();
        assert!(err.to_string().contains("chainId"), "{err}");
    }

    #[test]
    fn rejects_chain_id_mismatch() {
        let raw = genesis_json(FIXTURE_CHAIN_ID + 1);
        let err = decode_and_validate(&b64(&raw), FIXTURE_CHAIN_ID).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("5125") && msg.contains("5124"), "{msg}");
    }
}
