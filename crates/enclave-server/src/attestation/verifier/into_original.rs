//! Handles converting between the API and the original enums
//! This is necessary because if you import the original enums directly
//! in the API crate, it tries to build the entire attestation service crate,
//! which can break external projects

use attestation_service::Data;
use attestation_service::HashAlgorithm;
use seismic_enclave::request_types::coco_as::Data as ApiData;
use seismic_enclave::request_types::coco_as::HashAlgorithm as ApiHashAlgorithm;

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

pub trait IntoOriginalHashAlgorithm {
    fn into_original(self) -> HashAlgorithm;
}

impl IntoOriginalHashAlgorithm for ApiHashAlgorithm {
    fn into_original(self) -> HashAlgorithm {
        match self {
            ApiHashAlgorithm::Sha256 => HashAlgorithm::Sha256,
            ApiHashAlgorithm::Sha384 => HashAlgorithm::Sha384,
            ApiHashAlgorithm::Sha512 => HashAlgorithm::Sha512,
        }
    }
}
