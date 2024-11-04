
use tee_service_api::request_types::coco_as::Data as ApiData;
use tee_service_api::request_types::coco_as::HashAlgorithm as ApiHashAlgorithm;
use attestation_service::Data as OriginalData;
use attestation_service::HashAlgorithm as OriginalHashAlgorithm;
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