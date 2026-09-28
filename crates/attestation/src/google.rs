//! Google's endorsement of a GCE firmware build: the `VMLaunchEndorsement`
//! it publishes per MRTD, RSA-PSS-signed by a certificate under `GCE-cc-tcb-root`.
//! Fetched for live `gcp-tdx` evidence, archived beside it, and re-verified
//! offline on replay.

use prost::Message;
use rsa::RsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::pss::{Signature, VerifyingKey};
use rsa::signature::Verifier;
use sha2::Sha256;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use x509_parser::prelude::*;

/// Where Google publishes one endorsement per firmware MRTD.
const ENDORSEMENT_BUCKET: &str = "https://storage.googleapis.com/gce_tcb_integrity/ovmf_x64_csm";

/// `GCE-cc-tcb-root_1.crt` from `https://pki.goog/cloud_integrity/`, DER.
pub const GCE_CC_TCB_ROOT_DER: &[u8] = include_bytes!("../fixtures/gce-cc-tcb-root_1.der");
pub const GCE_CC_TCB_ROOT_NAME: &str = "GCE-cc-tcb-root_1";

const FETCH_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, PartialEq, Message)]
struct Endorsement {
    #[prost(bytes = "vec", tag = "1")]
    serialized_uefi_golden: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    signature: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
struct GoldenMeasurement {
    #[prost(bytes = "vec", tag = "4")]
    cert: Vec<u8>,
    #[prost(message, optional, tag = "8")]
    tdx: Option<Tdx>,
}

#[derive(Clone, PartialEq, Message)]
struct Tdx {
    #[prost(message, repeated, tag = "2")]
    measurements: Vec<TdxMeasurement>,
}

#[derive(Clone, PartialEq, Message)]
struct TdxMeasurement {
    #[prost(bytes = "vec", tag = "3")]
    mrtd: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum GoogleEndorsementError {
    #[error("fetching the endorsement: {0}")]
    Fetch(String),
    #[error("malformed endorsement: {0}")]
    Decode(#[from] prost::DecodeError),
    #[error("endorsement certificate: {0}")]
    Cert(String),
    #[error("endorsement certificate is not valid at the verification instant")]
    CertNotValidAt,
    #[error("endorsement certificate is not signed by {GCE_CC_TCB_ROOT_NAME}")]
    CertChain,
    #[error("endorsement public key: {0}")]
    Key(String),
    #[error("endorsement signature does not verify")]
    Signature,
    #[error("endorsement names no TDX measurements")]
    NoTdx,
    #[error("endorsement does not name MRTD {0}")]
    MrtdNotEndorsed(String),
}

/// Verify an endorsement at `at` (Unix seconds): its certificate is valid
/// then and signed by the pinned root, its signature holds, and it names `mrtd`.
pub fn verify_endorsement(
    endorsement: &[u8],
    mrtd: [u8; 48],
    at: u64,
) -> Result<(), GoogleEndorsementError> {
    let endorsement = Endorsement::decode(endorsement)?;
    let golden = GoldenMeasurement::decode(&*endorsement.serialized_uefi_golden)?;
    let (_, root) = X509Certificate::from_der(GCE_CC_TCB_ROOT_DER)
        .map_err(|e| GoogleEndorsementError::Cert(e.to_string()))?;
    let (_, leaf) = X509Certificate::from_der(&golden.cert)
        .map_err(|e| GoogleEndorsementError::Cert(e.to_string()))?;
    let at = i64::try_from(at)
        .ok()
        .and_then(|at| ASN1Time::from_timestamp(at).ok())
        .ok_or(GoogleEndorsementError::CertNotValidAt)?;
    if !leaf.validity().is_valid_at(at) {
        return Err(GoogleEndorsementError::CertNotValidAt);
    }
    leaf.verify_signature(Some(root.public_key()))
        .map_err(|_| GoogleEndorsementError::CertChain)?;
    let key = RsaPublicKey::from_public_key_der(leaf.public_key().raw)
        .map_err(|e| GoogleEndorsementError::Key(e.to_string()))?;
    let signature = Signature::try_from(&*endorsement.signature)
        .map_err(|_| GoogleEndorsementError::Signature)?;
    VerifyingKey::<Sha256>::new(key)
        .verify(&endorsement.serialized_uefi_golden, &signature)
        .map_err(|_| GoogleEndorsementError::Signature)?;
    let tdx = golden.tdx.ok_or(GoogleEndorsementError::NoTdx)?;
    if tdx.measurements.iter().any(|m| m.mrtd == mrtd) {
        Ok(())
    } else {
        Err(GoogleEndorsementError::MrtdNotEndorsed(hex::encode(mrtd)))
    }
}

static ENDORSEMENTS: Mutex<BTreeMap<[u8; 48], Arc<Vec<u8>>>> = Mutex::new(BTreeMap::new());

/// Google's endorsement of `mrtd`, fetched once per process and verified at `at`.
pub async fn endorsement_for(
    mrtd: [u8; 48],
    at: u64,
) -> Result<Arc<Vec<u8>>, GoogleEndorsementError> {
    let cached = ENDORSEMENTS.lock().unwrap().get(&mrtd).cloned();
    if let Some(bytes) = cached {
        verify_endorsement(&bytes, mrtd, at)?;
        return Ok(bytes);
    }
    let url = format!("{ENDORSEMENT_BUCKET}/tdx/{}.binarypb", hex::encode(mrtd));
    let fetch = |e: reqwest::Error| GoogleEndorsementError::Fetch(format!("{url}: {e}"));
    let response = reqwest::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .build()
        .map_err(fetch)?
        .get(&url)
        .send()
        .await
        .map_err(fetch)?;
    if !response.status().is_success() {
        return Err(GoogleEndorsementError::Fetch(format!(
            "{url}: HTTP {}",
            response.status()
        )));
    }
    let bytes = response.bytes().await.map_err(fetch)?.to_vec();
    verify_endorsement(&bytes, mrtd, at)?;
    let bytes = Arc::new(bytes);
    ENDORSEMENTS.lock().unwrap().insert(mrtd, bytes.clone());
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

    /// Google's endorsement of the c3-standard-4 firmware a devnet founder
    /// booted on 2026-10-01, and that quote's MRTD and verification instant.
    const ENDORSEMENT: &[u8] = include_bytes!("../fixtures/gce-endorsement-c3-standard-4.binarypb");
    const MRTD: &str = "c1ee9c16e3afc506cfe042c5b846a368528f3b37618eafb27469bc114cf914e9222c91618470e7f2b28ac360968270a5";
    const AT: u64 = 1_790_873_673;

    fn mrtd() -> [u8; 48] {
        hex::decode(MRTD).unwrap().try_into().unwrap()
    }

    #[test]
    fn the_fixture_endorses_the_firmware_it_was_fetched_for() {
        verify_endorsement(ENDORSEMENT, mrtd(), AT).unwrap();
    }

    #[test]
    fn another_mrtd_is_not_endorsed() {
        assert!(matches!(
            verify_endorsement(ENDORSEMENT, [0x11; 48], AT),
            Err(GoogleEndorsementError::MrtdNotEndorsed(_))
        ));
    }

    #[test]
    fn a_tampered_signature_or_body_fails() {
        let mut tampered = ENDORSEMENT.to_vec();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(matches!(
            verify_endorsement(&tampered, mrtd(), AT),
            Err(GoogleEndorsementError::Signature)
        ));
        let mut tampered = ENDORSEMENT.to_vec();
        tampered[64] ^= 1;
        assert!(verify_endorsement(&tampered, mrtd(), AT).is_err());
        assert!(matches!(
            verify_endorsement(&ENDORSEMENT[..100], mrtd(), AT),
            Err(GoogleEndorsementError::Decode(_))
        ));
    }

    #[test]
    fn outside_the_certificates_validity_fails() {
        assert!(matches!(
            verify_endorsement(ENDORSEMENT, mrtd(), 2_000_000_000),
            Err(GoogleEndorsementError::CertNotValidAt)
        ));
    }

    #[test]
    fn the_pinned_root_is_the_published_one() {
        assert_eq!(
            hex::encode(Sha256::digest(GCE_CC_TCB_ROOT_DER)),
            "e876bc6978bf4f3da445f98a0a82363c8c0bae5a1fc033c6df65846a6cb0f18c"
        );
    }
}
