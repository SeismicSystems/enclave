//! Handles converting between the API and the original enums
//! This is necessary because if you import the original enums directly
//! in the API crate, it tries to build the entire attestation service crate,
//! which can break external projects

pub use attestation_service::Data as OriginalData;
pub use attestation_service::HashAlgorithm as OriginalHashAlgorithm;
use seismic_enclave::request_types::coco_as::Data as ApiData;
use seismic_enclave::request_types::coco_as::HashAlgorithm as ApiHashAlgorithm;

pub trait IntoOriginalData {
    fn into_original(self) -> OriginalData;
}

impl IntoOriginalData for ApiData {
    fn into_original(self) -> OriginalData {
        match self {
            ApiData::Raw(bytes) => OriginalData::Raw(bytes),
            ApiData::Structured(value) => OriginalData::Structured(value),
        }
    }
}

pub trait IntoOriginalHashAlgorithm {
    fn into_original(self) -> OriginalHashAlgorithm;
}

impl IntoOriginalHashAlgorithm for ApiHashAlgorithm {
    fn into_original(self) -> OriginalHashAlgorithm {
        match self {
            ApiHashAlgorithm::Sha256 => OriginalHashAlgorithm::Sha256,
            ApiHashAlgorithm::Sha384 => OriginalHashAlgorithm::Sha384,
            ApiHashAlgorithm::Sha512 => OriginalHashAlgorithm::Sha512,
        }
    }
}
