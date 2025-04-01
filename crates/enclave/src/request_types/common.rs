/// Below is from https://github.com/confidential-containers/trustee/blob/main/attestation-service/src/lib.rs#L264
/// so that we can wrap around without declaring the dependency client-side
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384, Sha512};
use serde_json::Value;
use std::fmt;
use std::str::FromStr;

/// Our canonical HashAlgorithm definition 
/// This will be the type used everywhere in our public API
#[derive(Clone, Debug, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgorithm {
    /// Return the hash value length in bytes
    pub fn digest_len(&self) -> usize {
        match self {
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha384 => 48,
            HashAlgorithm::Sha512 => 64,
        }
    }

    pub fn digest(&self, material: &[u8]) -> Vec<u8> {
        match self {
            HashAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(material);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha384 => {
                let mut hasher = Sha384::new();
                hasher.update(material);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha512 => {
                let mut hasher = Sha512::new();
                hasher.update(material);
                hasher.finalize().to_vec()
            }
        }
    }

    /// Return a list of all supported hash algorithms.
    pub fn list_all() -> Vec<Self> {
        vec![HashAlgorithm::Sha256, HashAlgorithm::Sha384, HashAlgorithm::Sha512]
    }
}

impl Default for HashAlgorithm {
    fn default() -> Self {
        Self::Sha384
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HashAlgorithm::Sha256 => write!(f, "sha256"),
            HashAlgorithm::Sha384 => write!(f, "sha384"),
            HashAlgorithm::Sha512 => write!(f, "sha512"),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParseHashAlgorithmError;

impl fmt::Display for ParseHashAlgorithmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ParseHashAlgorithmError")
    }
}

impl std::error::Error for ParseHashAlgorithmError {}

impl FromStr for HashAlgorithm {
    type Err = ParseHashAlgorithmError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let cleaned = s.replace('-', "").to_lowercase();
        match cleaned.as_str() {
            "sha256" => Ok(HashAlgorithm::Sha256),
            "sha384" => Ok(HashAlgorithm::Sha384),
            "sha512" => Ok(HashAlgorithm::Sha512),
            _ => Err(ParseHashAlgorithmError),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Data {
    /// Raw data (bytes) to check against
    Raw(Vec<u8>),

    /// A JSON object that will be canonicalized and hashed
    Structured(Value),
}
