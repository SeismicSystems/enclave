//! Handles converting between the API and the original enums
//! This is necessary because if you import the original enums directly
//! in the API crate, it tries to build the entire attestation service crate,
//! which can break external projects

use seismic_enclave::request_types::common::{HashAlgorithm, Data};

impl From<HashAlgorithm> for attestation_service::HashAlgorithm {
        fn from(algo: HashAlgorithm) -> Self {
            match algo {
                HashAlgorithm::Sha256 => attestation_service::HashAlgorithm::Sha256,
                HashAlgorithm::Sha384 => attestation_service::HashAlgorithm::Sha384,
                HashAlgorithm::Sha512 => attestation_service::HashAlgorithm::Sha512,
            }
        }
    }
    
impl From<attestation_service::HashAlgorithm> for HashAlgorithm {
    fn from(algo: attestation_service::HashAlgorithm) -> Self {
        match algo {
            attestation_service::HashAlgorithm::Sha256 => HashAlgorithm::Sha256,
            attestation_service::HashAlgorithm::Sha384 => HashAlgorithm::Sha384,
            attestation_service::HashAlgorithm::Sha512 => HashAlgorithm::Sha512,
        }
    }
}

impl From<Data> for attestation_service::Data {
    fn from(data: Data) -> Self {
        match data {
            Data::Raw(bytes) => attestation_service::Data::Raw(bytes),
            Data::Structured(value) => attestation_service::Data::Structured(value),
        }
    }
}

impl From<attestation_service::Data> for Data {
    fn from(data: attestation_service::Data) -> Self {
        match data {
            attestation_service::Data::Raw(bytes) => Data::Raw(bytes),
            attestation_service::Data::Structured(value) => Data::Structured(value),
        }
    }
}

