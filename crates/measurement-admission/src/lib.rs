//! Measurement admission: the versioned mapping from verified TEE guest
//! measurements to the opaque `bytes32` admission IDs the on-chain
//! `MeasurementRegistry` stores, plus the compiler that turns a
//! measurement-policy document into the exact set of IDs it admits and the
//! registry genesis storage seeding them.
//!
//! Every admission decision is one predicate:
//!
//! ```text
//! verified guest measurements -> canonical admission ID -> accepted-ID set
//! ```
//!
//! Only the source of the accepted set differs by consumer: the responder
//! queries `MeasurementRegistry.isAccepted(id)` on local reth, while the
//! joiner and deploy tooling compile the manifest-pinned policy artifact
//! with [`compile_policy`]. Both sides share this crate's normalization
//! and ID derivation, so the two halves of a handshake cannot disagree on
//! what "acceptable" means.
//!
//! Admission IDs are keccak-256 over ABI-encoded words because they key
//! Solidity mapping storage — the ID lives in the EVM's hash domain end to
//! end, from `isAccepted(bytes32)` down to the genesis storage slots in
//! [`genesis`]. (The SHA-256 conventions in `seismic-attestation::bindings`
//! and `seismic-network-manifest` cover transcripts and artifacts, which
//! never key chain state.)

use alloy_primitives::{B256, keccak256};
use serde::Serialize;
use std::{collections::HashMap, fmt};

pub mod genesis;
pub mod policy;
pub mod promote;
pub mod report;

pub use policy::{CompiledPolicy, CompiledRecord, PolicyError, compile_policy};
pub use promote::{PromoteError, promote_measurements};
pub use report::CompileReport;

/// One guest identity, in the form the on-chain `MeasurementRegistry` keys
/// it: `keccak256(abi.encode(schema_id, <schema registers>))`.
///
/// The name says what the value is *for*, and the purpose is also what
/// defines the value. An admission ID keys exactly one decision —
/// `isAccepted(id)` — and identifies the equivalence class of guests that
/// are indistinguishable for admission purposes: every machine booting the
/// same measured image derives the same ID, and registers outside the
/// schema never contribute. It is deliberately not a "guest ID" or "VM ID".
/// Nothing about the instance, machine, or operator is in it, and there is
/// no schema-independent identity of a guest — which registers count is
/// itself a policy choice, pinned by the schema word in the preimage. A
/// different register set or attestation backend is a new schema and a
/// deliberately disjoint ID space.
///
/// The derivation is one-way but never opaque: the published policy
/// document lists every accepted identity in preimage form (its register
/// values, one record per identity), so each ID is recomputable from the
/// reviewed document. Serialized and displayed as lowercase 0x-hex;
/// converts to/from [`B256`] at ABI and storage boundaries, where wrapping
/// asserts nothing — a wrapped value means something only if it came from
/// this derivation or from the registry.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct AdmissionId(B256);

impl AdmissionId {
    pub const fn as_b256(&self) -> &B256 {
        &self.0
    }
}

impl From<B256> for AdmissionId {
    fn from(word: B256) -> Self {
        Self(word)
    }
}

impl From<AdmissionId> for B256 {
    fn from(id: AdmissionId) -> Self {
        id.0
    }
}

impl fmt::Display for AdmissionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for AdmissionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AdmissionId({})", self.0)
    }
}

/// Azure TDX v1 admission schema: a Seismic guest image on Azure is
/// identified by the correlated vTPM register tuple `(PCR4, PCR9, PCR11)`.
///
/// A different register set or attestation backend is a new schema name (and
/// therefore a disjoint admission-ID space); it never reinterprets this one.
pub const AZURE_TDX_V1_SCHEMA: &str = "seismic.azure-tdx.pcr4-pcr9-pcr11.v1";

/// The `attestation_type` value (as in attested-tls policy documents) whose
/// records compile under [`AZURE_TDX_V1_SCHEMA`].
pub const AZURE_TDX_ATTESTATION_TYPE: &str = "azure-tdx";

/// PCR indexes bound by the Azure TDX v1 schema, in preimage order.
pub const AZURE_TDX_V1_PCRS: [u32; 3] = [4, 9, 11];

/// Domain-separation word for Azure TDX v1 admission preimages:
/// `keccak256(AZURE_TDX_V1_SCHEMA)`. Pinned by a golden test.
pub fn azure_tdx_v1_schema_id() -> B256 {
    keccak256(AZURE_TDX_V1_SCHEMA.as_bytes())
}

/// One Azure TDX v1 measurement tuple: a complete guest identity under the
/// schema. Values are SHA-256 vTPM PCR digests.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AzureTdxV1Measurements {
    pub pcr4: B256,
    pub pcr9: B256,
    pub pcr11: B256,
}

impl AzureTdxV1Measurements {
    /// This tuple's [`AdmissionId`]:
    /// `keccak256(abi.encode(schemaId, pcr4, pcr9, pcr11))`. All four fields
    /// are static 32-byte words, so the ABI encoding is their concatenation —
    /// fixed-width, unambiguous, and recomputable by a future on-chain
    /// catalog from the same preimage.
    pub fn admission_id(&self) -> AdmissionId {
        let mut preimage = [0u8; 128];
        preimage[..32].copy_from_slice(azure_tdx_v1_schema_id().as_slice());
        preimage[32..64].copy_from_slice(self.pcr4.as_slice());
        preimage[64..96].copy_from_slice(self.pcr9.as_slice());
        preimage[96..128].copy_from_slice(self.pcr11.as_slice());
        AdmissionId(keccak256(preimage))
    }

    /// Extract the schema tuple from a verified PCR map (the shape evidence
    /// verification produces). Fails closed: a map missing any schema PCR
    /// yields an error, not a partial identity. Registers outside the schema
    /// are ignored — guest identity is exactly the schema tuple.
    pub fn from_pcrs(pcrs: &HashMap<u32, [u8; 32]>) -> Result<Self, MissingPcr> {
        let pcr = |index: u32| {
            pcrs.get(&index)
                .copied()
                .map(B256::from)
                .ok_or(MissingPcr(index))
        };
        Ok(Self {
            pcr4: pcr(4)?,
            pcr9: pcr(9)?,
            pcr11: pcr(11)?,
        })
    }
}

/// A verified PCR map did not contain a register the schema requires.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("verified measurements are missing pcr{0}, required by {AZURE_TDX_V1_SCHEMA}")]
pub struct MissingPcr(pub u32);

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::b256;

    // Golden vectors, cross-checked against an independent keccak
    // implementation (`cast keccak`). They pin the v1 derivation across
    // implementations and releases and must never change.
    const SCHEMA_ID: B256 =
        b256!("0x3638c716e69d8604498bdfc48902b7a798c977e5b6e2cf74586e6d609bb09684");
    const GOLDEN_TUPLE: AzureTdxV1Measurements = AzureTdxV1Measurements {
        pcr4: b256!("0x1111111111111111111111111111111111111111111111111111111111111111"),
        pcr9: b256!("0x2222222222222222222222222222222222222222222222222222222222222222"),
        pcr11: b256!("0x3333333333333333333333333333333333333333333333333333333333333333"),
    };
    const GOLDEN_ADMISSION_ID: B256 =
        b256!("0x0e4c78c6346c15ad1fbbcf16dab1ab9e5c820f4daf5b8001c92d1f40f0f16a8e");

    #[test]
    fn schema_id_golden() {
        assert_eq!(azure_tdx_v1_schema_id(), SCHEMA_ID);
    }

    #[test]
    fn admission_id_golden() {
        assert_eq!(
            GOLDEN_TUPLE.admission_id(),
            AdmissionId::from(GOLDEN_ADMISSION_ID)
        );
    }

    #[test]
    fn from_pcrs_extracts_schema_registers_and_ignores_others() {
        let mut pcrs = HashMap::new();
        pcrs.insert(4, GOLDEN_TUPLE.pcr4.0);
        pcrs.insert(9, GOLDEN_TUPLE.pcr9.0);
        pcrs.insert(11, GOLDEN_TUPLE.pcr11.0);
        // Evidence carries the full bank; extra registers don't perturb identity.
        pcrs.insert(0, [0xaa; 32]);
        pcrs.insert(7, [0xbb; 32]);
        assert_eq!(AzureTdxV1Measurements::from_pcrs(&pcrs), Ok(GOLDEN_TUPLE));
    }

    #[test]
    fn from_pcrs_fails_closed_on_missing_register() {
        let mut pcrs = HashMap::new();
        pcrs.insert(4, GOLDEN_TUPLE.pcr4.0);
        pcrs.insert(11, GOLDEN_TUPLE.pcr11.0);
        assert_eq!(AzureTdxV1Measurements::from_pcrs(&pcrs), Err(MissingPcr(9)));
    }
}
