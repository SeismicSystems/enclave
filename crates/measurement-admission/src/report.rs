//! Serializable compile report: the language-neutral rendering of one
//! compiled policy. Rendering is deterministic (fixed field order, sorted
//! maps, pretty-printed with a trailing newline), so a committed report is
//! a byte-exact golden vector for every stack that touches the pipeline,
//! including ones that cannot link this crate (Solidity tests, spec worked
//! examples, non-Rust deploy tooling via the CLI). It also serves as the
//! durable audit record of what a policy document compiled to and seeded
//! at genesis.

use crate::{AZURE_TDX_V1_SCHEMA, AdmissionId, CompiledPolicy, azure_tdx_v1_schema_id, genesis};
use alloy_primitives::B256;
use serde::Serialize;
use std::collections::BTreeMap;

/// Everything deploy needs from one compiled policy document.
#[derive(Clone, Debug, Serialize)]
pub struct CompileReport {
    /// Admission schema every record compiled under.
    pub schema: &'static str,
    /// `keccak256(schema)`, the admission preimage's domain-separation word.
    pub schema_id: B256,
    /// SHA-256 of the exact policy document bytes (the manifest's
    /// `bootstrap_policy_hash` and the genesis policy-hash slots).
    pub policy_hash: B256,
    /// Number of unique admission IDs (the registry's `acceptedCount`).
    pub accepted_count: usize,
    /// Unique admission IDs across all records, ascending.
    pub admission_ids: Vec<AdmissionId>,
    /// Per-record expansions, in document order.
    pub records: Vec<RecordReport>,
    /// keccak256 of the canonical registry runtime bytecode the genesis
    /// storage below pairs with ([`genesis::REGISTRY_RUNTIME_CODE_HASH`]).
    pub registry_runtime_code_hash: B256,
    /// Complete registry genesis storage (slot -> value).
    pub registry_genesis_storage: BTreeMap<B256, B256>,
}

/// One record's audit label and the admission ID it compiles to.
#[derive(Clone, Debug, Serialize)]
pub struct RecordReport {
    pub measurement_id: String,
    /// The admission ID of this record's measurement tuple.
    pub admission_id: AdmissionId,
}

impl CompileReport {
    pub fn new(policy: &CompiledPolicy) -> Self {
        Self {
            schema: AZURE_TDX_V1_SCHEMA,
            schema_id: azure_tdx_v1_schema_id(),
            policy_hash: policy.policy_hash,
            accepted_count: policy.admission_ids.len(),
            admission_ids: policy.admission_ids.clone(),
            records: policy
                .records
                .iter()
                .map(|record| RecordReport {
                    measurement_id: record.measurement_id.clone(),
                    admission_id: record.admission_id(),
                })
                .collect(),
            registry_runtime_code_hash: genesis::REGISTRY_RUNTIME_CODE_HASH,
            registry_genesis_storage: genesis::registry_genesis_storage(policy),
        }
    }

    /// Canonical rendering: 2-space pretty JSON, single trailing newline.
    pub fn to_json(&self) -> String {
        let mut rendered =
            serde_json::to_string_pretty(self).expect("report serialization is infallible");
        rendered.push('\n');
        rendered
    }
}
