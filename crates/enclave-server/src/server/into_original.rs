//! Handles converting between the API and the original enums
//! These duplicate types are necessary because of Rust's orphan rule
//! and the conversion code cannot live in the seismic-enclave crate because
//! if you import the original enums directly in the API crate,
//! seismic-enclave builds the entire attestation service dependency,
//! which can break external projects like Reth

use attestation_service::Data;
use seismic_enclave::request_types::Data as ApiData;

pub trait IntoOriginalData {
    fn into_original(self) -> Data;
}

impl IntoOriginalData for ApiData {
    fn into_original(self) -> Data {
        match self {
            ApiData::Raw(bytes) => Data::Raw(bytes),
            ApiData::Structured(value) => Data::Structured(value),
        }
    }
}
