//! Handles converting between the API and the original enums
//! These duplicate types are necessary because of Rust's orphan rule
//! and the conversion code cannot live in the seismic-enclave crate because
//! if you import the original enums directly in the API crate,
//! seismic-enclave builds the entire attestation service dependency,
//! which can break external projects like Reth

use attestation_service::RuntimeData;
use seismic_enclave::request_types::Data as ApiData;

pub trait IntoOriginalData {
    fn into_original(self) -> RuntimeData;
}

impl IntoOriginalData for ApiData {
    fn into_original(self) -> RuntimeData {
        match self {
            ApiData::Raw(bytes) => RuntimeData::Raw(bytes),
            ApiData::Structured(value) => RuntimeData::Structured(value),
        }
    }
}
