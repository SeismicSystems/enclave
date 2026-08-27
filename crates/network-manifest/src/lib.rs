//! Schema for `network-manifest.json` and derivation of the [`NetworkId`]
//! that every transcript binding consumes.
//!
//! This crate is deliberately dependency-light (serde + sha2): parsing the
//! manifest and deriving `network_id` must be possible without the
//! attestation stack — in the boot binary (tdx-init) and in deploy-side
//! manifest tooling. Consumers that also verify evidence depend on
//! `seismic-attestation`, which builds on this crate and re-exports it.
//!
//! The manifest is the deploy-time artifact that defines a network's identity:
//! `network_id = SHA-256(exact file bytes)`. The file travels as opaque bytes
//! through every hop (deploy artifact → node.toml embed → tdx-init → network-manifest.json).
//! Consumers hash the bytes they read themselves rather than trusting a precomputed id.
//!
//! This crate deliberately implements `Deserialize` only. The manifest's sole
//! emitter is the `seismic-manifest` crate (`bin/seismic-manifest`), which
//! deploy tooling links or runs; nothing on the node side may
//! parse-and-re-serialize the file, because any re-rendering risks changing the
//! bytes and therefore the `network_id`. The emitter renders deterministically
//! (2-space indent, key-sorted, single trailing newline); the parser accepts
//! any key order — ordering matters only because the bytes are hashed.

use serde::{Deserialize, Deserializer};
use sha2::{Digest, Sha256};
use std::fmt;
use thiserror::Error;

/// A network's identity: SHA-256 of the exact bytes of its
/// `network-manifest.json`.
///
/// Note that we don't serialize before hashing on purpose. We want the
/// artifact itself to be the identity, not its values. This is similar to
/// git objects, OCI digests, and other content-addressed objects. The manifest
/// has a single emitter and travels verbatim, so any holder of the bytes
/// derives the id with no schema and no canonical-JSON spec that every
/// language must reimplement bit-identically, and there is no canonicalizer
/// whose bugs could silently give two differing documents one id. The flip
/// side is intended: any byte change, even a reformat, names a different
/// network and fails loudly at the first binding check.
///
/// Transcript form is the raw 32 bytes ([`NetworkId::as_bytes`]).
/// Presentation form is lowercase 0x-hex ([`fmt::Display`]).
/// Equivalently: `sha256sum network-manifest.json`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct NetworkId([u8; 32]);

impl NetworkId {
    /// Derive the id from manifest file bytes. Hash the same bytes you parse.
    pub fn from_manifest_bytes(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    /// Wrap an already-computed id (e.g. received in an addendum or test vector).
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for NetworkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

impl fmt::Debug for NetworkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NetworkId({self})")
    }
}

/// Parsed `network-manifest.json` (schema v1).
///
/// A network's identity must be unique at every layer where signatures or
/// transcripts could leak across chains, and the manifest carries one
/// separator per layer:
///
/// - `eth.chain_id` — kills transaction replay (EIP-155): a tx signed for one
///   network is invalid on another.
/// - `summit.genesis_config_digest` (via `network_id`) — kills
///   attestation-transcript replay: quotes and root-key handshake bindings
///   from one network can't verify on a clone deployment. The digest covers
///   the validator pubkeys harvested during that founding, so two foundings
///   cannot share one — distinct deployments get distinct `network_id`s by
///   construction, with no authored nonce needed.
/// - `summit.namespace` — kills BLS consensus-signature replay: without a
///   distinct signing domain, a validator key active on two chains (cloned
///   devnets, a fork) produces votes valid on both — manufactured
///   equivocation.
///
/// Only `summit.genesis_config_digest` differs between clone deployments for
/// free; operators must vary `eth.chain_id` and `summit.namespace` too for the
/// other two layers to hold.
///
/// Parsing is strict: unknown keys are rejected, so two verifiers can never
/// disagree on field semantics. New fields require `manifest_version = 2` and
/// a `NetworkManifestV2` type. Strictness is about semantics only —
/// `network_id` hashes raw bytes, so an unknown field could never silently
/// change the id.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkManifestV1 {
    pub manifest_version: u64,
    /// Human label; intentionally part of the hash (intent is identity).
    pub name: String,
    pub eth: EthManifest,
    pub summit: SummitManifest,
    pub measurements: MeasurementsManifest,
}

/// Execution-layer (reth) identity.
///
/// Both fields are needed: `genesis_hash` covers the header (state root,
/// alloc) but not `config.chainId`, which lives outside the header — so the
/// chain id is an independent commitment, not derivable from the hash.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EthManifest {
    /// Must equal `config.chainId` inside the reth genesis JSON (deploy-time
    /// cross-artifact validation; not checked here).
    pub chain_id: u64,
    /// `keccak(rlp(header(reth-genesis.json)))`; commits to the full genesis
    /// alloc including `MeasurementRegistry` initial measurements.
    #[serde(deserialize_with = "hex_32")]
    pub genesis_hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SummitManifest {
    /// Summit's own `config_digest` of the complete founding `genesis.toml`:
    /// SHA-256 over summit's domain-prefixed SSZ serialization, computed by
    /// `summit genesis digest <file>`. Covers the consensus parameters plus
    /// every validator's ed25519 node pubkey, BLS consensus pubkey, and
    /// withdrawal credentials; excludes `ip_address` (summit annotates it
    /// "network topology, not consensus identity"), so refreshing a
    /// delivered IP never changes `network_id`. It is also the value summit
    /// derives `chain_domain` from, so live nodes already enforce agreement
    /// on everything it covers.
    #[serde(deserialize_with = "hex_32")]
    pub genesis_config_digest: [u8; 32],
    /// BLS signature domain separator; duplicated from the genesis so
    /// verifiers don't need to parse TOML.
    pub namespace: String,
}

/// The TEE admission policy: which measurements may join, and who decides.
///
/// The same measurement set exists in two representations: the bootstrap
/// artifact pinned by `bootstrap_policy_hash` (the joiner's source — readable
/// before it can read any chain state) and `MeasurementRegistry` genesis storage
/// (the responder's source). Their consistency at genesis is a deploy-time
/// validation; afterwards the contract carries the live policy while the
/// artifact stays frozen.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeasurementsManifest {
    /// SHA-256 of the measurement-policy artifact bytes, eg:
    /// <https://github.com/flashbots/attested-tls/blob/f3b47739d17650a9489c8707cd94d0e80751ec40/crates/attestation/test-assets/measurements.json>
    /// Produced by seismic-images' `make measure`, and lands under `build/measurements.json`.
    /// `seismic-attestation`'s `SeismicMeasurementPolicy` parses this file.
    ///
    /// Pins the *bootstrap* policy only — the measurement set in force at
    /// genesis, frozen forever by this hash. Post-genesis additions and
    /// deprecations happen on-chain in `contracts.registry`; read the
    /// contract, not this artifact, for the current allowlist.
    #[serde(deserialize_with = "hex_32")]
    pub bootstrap_policy_hash: [u8; 32],
    pub contracts: ContractsManifest,
}

/// Addresses of the admission-policy contracts, duplicated from the genesis
/// alloc for verifiers that don't hold the genesis file.
///
/// Fields are named by role, not by contract class name, so the hashed
/// artifact schema survives contract renames. The registry's well-known
/// genesis-predeploy address is also exposed as
/// `seismic_measurement_registry_client::MEASUREMENT_REGISTRY_ADDRESS`.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractsManifest {
    /// The measurement registry (`MeasurementRegistry.sol`): the allowlist
    /// new Seismic nodes are checked against (`isAccepted()`). This is the
    /// *live* policy, updated on-chain over the network's lifetime —
    /// `bootstrap_policy_hash` freezes only the genesis-time set.
    #[serde(deserialize_with = "hex_20")]
    pub registry: [u8; 20],
    /// The authority allowed to mutate the registry (today
    /// `MeasurementAuthorityDev.sol`).
    #[serde(deserialize_with = "hex_20")]
    pub authority: [u8; 20],
}

impl NetworkManifestV1 {
    /// The `manifest_version` value this schema corresponds to.
    pub const VERSION: u64 = 1;

    /// Strictly parse manifest bytes against the v1 schema.
    ///
    /// Callers that also need the `network_id` must derive it from the same
    /// bytes via [`NetworkId::from_manifest_bytes`] — never from a
    /// re-serialization of the parsed value.
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, ManifestError> {
        // Probe the version before the strict parse: a future-version manifest
        // carries fields this schema doesn't know, and "unsupported
        // manifest_version 2" is the actionable error, not "unknown field".
        #[derive(Deserialize)]
        struct VersionProbe {
            manifest_version: u64,
        }
        let probe: VersionProbe = serde_json::from_slice(bytes)?;
        if probe.manifest_version != Self::VERSION {
            return Err(ManifestError::UnsupportedVersion {
                found: probe.manifest_version,
            });
        }
        Ok(serde_json::from_slice(bytes)?)
    }
}

#[derive(Debug, Error)]
pub enum ManifestError {
    #[error(
        "manifest does not match schema v{version}: {0}",
        version = NetworkManifestV1::VERSION
    )]
    Json(#[from] serde_json::Error),
    #[error(
        "unsupported manifest_version {found}; this parser implements v{}",
        NetworkManifestV1::VERSION
    )]
    UnsupportedVersion { found: u64 },
}

fn hex_32<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
    decode_fixed_hex(deserializer)
}

fn hex_20<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 20], D::Error> {
    decode_fixed_hex(deserializer)
}

fn decode_fixed_hex<'de, D: Deserializer<'de>, const N: usize>(
    deserializer: D,
) -> Result<[u8; N], D::Error> {
    let s = String::deserialize(deserializer)?;
    let digits = s.strip_prefix("0x").ok_or_else(|| {
        serde::de::Error::custom(format!("expected 0x-prefixed hex string, got {s:?}"))
    })?;
    let mut bytes = [0u8; N];
    hex::decode_to_slice(digits, &mut bytes).map_err(|err| {
        serde::de::Error::custom(format!("expected {N}-byte hex string, got {s:?}: {err}"))
    })?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Rendered by the canonical emitter (`bin/seismic-manifest`, whose
    /// round-trip test holds `parse → render` to these exact bytes): 2-space
    /// indent, key-sorted, single trailing newline. Key order is irrelevant
    /// to the parser but is part of the hashed bytes; regenerate the pinned
    /// `network_id` below whenever the fixture changes.
    const FIXTURE: &[u8] = include_bytes!("../fixtures/network-manifest-v1.json");

    #[test]
    fn parses_v1_fixture_and_derives_network_id() {
        let manifest = NetworkManifestV1::from_json_bytes(FIXTURE).unwrap();

        assert_eq!(manifest.manifest_version, 1);
        assert_eq!(manifest.name, "seismic-devnet-3");
        assert_eq!(manifest.eth.chain_id, 5124);
        assert_eq!(
            hex::encode(manifest.eth.genesis_hash),
            "78ab9057bb67f95a6182969c5d755ac02802c98c0d2f0d8daeb52f4bddc60be5"
        );
        assert_eq!(manifest.summit.genesis_config_digest, [0xBB; 32]);
        assert_eq!(manifest.summit.namespace, "seismic-devnet-3");
        assert_eq!(manifest.measurements.bootstrap_policy_hash, [0xCC; 32]);
        assert_eq!(
            hex::encode(manifest.measurements.contracts.registry),
            "1000000000000000000000000000000000000001"
        );
        assert_eq!(
            hex::encode(manifest.measurements.contracts.authority),
            "1000000000000000000000000000000000000002"
        );

        // Stable vector: sha256sum of the fixture file. Display is the
        // presentation form (lowercase 0x-hex).
        let network_id = NetworkId::from_manifest_bytes(FIXTURE);
        assert_eq!(
            network_id.to_string(),
            "0x8ef142e3f2bf15f8b201c4d8cda7848a9e846222c62b5615d4d36c7fccd98a24"
        );
    }

    // The byte-exactness rule: network_id is a hash of bytes, not of parsed
    // content, so a cosmetic edit (trailing newline) is a different network.
    #[test]
    fn network_id_is_over_raw_bytes_not_parsed_content() {
        let mut edited = FIXTURE.to_vec();
        edited.push(b'\n');
        assert_eq!(
            NetworkManifestV1::from_json_bytes(&edited).unwrap(),
            NetworkManifestV1::from_json_bytes(FIXTURE).unwrap()
        );
        assert_ne!(
            NetworkId::from_manifest_bytes(&edited),
            NetworkId::from_manifest_bytes(FIXTURE)
        );
    }

    /// Parse the fixture after applying `mutate` to its JSON value.
    fn parse_mutated(
        mutate: impl FnOnce(&mut serde_json::Value),
    ) -> Result<NetworkManifestV1, ManifestError> {
        let mut value: serde_json::Value = serde_json::from_slice(FIXTURE).unwrap();
        mutate(&mut value);
        NetworkManifestV1::from_json_bytes(&serde_json::to_vec(&value).unwrap())
    }

    #[test]
    fn rejects_unknown_fields() {
        let result = parse_mutated(|v| v["tx_io_pk"] = "0x02ab".into());
        assert!(matches!(result, Err(ManifestError::Json(_))));
    }

    #[test]
    fn reports_unsupported_version_before_unknown_fields() {
        // A v2 manifest carries fields this schema doesn't know; the error
        // must name the version, not the first unknown field.
        let result = parse_mutated(|v| {
            v["manifest_version"] = 2.into();
            v["some_v2_field"] = "new".into();
        });
        assert!(matches!(
            result,
            Err(ManifestError::UnsupportedVersion { found: 2 })
        ));
    }

    #[test]
    fn rejects_malformed_hex_fields() {
        // wrong length for a 32-byte field
        let result = parse_mutated(|v| {
            v["summit"]["genesis_config_digest"] = format!("0x{}", "bb".repeat(31)).into()
        });
        assert!(matches!(result, Err(ManifestError::Json(_))));

        // missing 0x prefix
        let result = parse_mutated(|v| v["eth"]["genesis_hash"] = "ab".repeat(32).into());
        assert!(matches!(result, Err(ManifestError::Json(_))));

        // non-hex digits
        let result = parse_mutated(|v| {
            v["measurements"]["bootstrap_policy_hash"] = format!("0x{}", "zz".repeat(32)).into()
        });
        assert!(matches!(result, Err(ManifestError::Json(_))));
    }
}
