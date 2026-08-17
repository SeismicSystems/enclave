//! The service's JSON-RPC error contract.
//!
//! Five codes reach a caller, and a joining node in another process decides
//! what to do next from the code alone: whether its evidence yielded no
//! appraisable identity, whether that identity is not accepted, or whether this
//! responder could not answer. Every message is a stable constant — an
//! unauthenticated caller learns the outcome and nothing about why — so the
//! failure detail lives in this responder's log instead.
//!
//! The two denials are terminal, read by the joiner's operator as *your*
//! configuration is wrong, so each is only sent when this responder positively
//! attributed the failure. Anything it cannot attribute answers as an internal
//! error, blaming neither party.
//!
//! Both requester-facing boundaries are checkable by the caller anyway: DCAP
//! verification is local and offline, and the accepted set is a public
//! `isAccepted` view on a public chain. Naming which of the two it hit hands a
//! caller nothing it could not determine for itself.

use crate::{
    admission::{AdmissionDenial, DenialKind},
    bootstrap::AnswerError,
};
use jsonrpsee::types::{ErrorCode, ErrorObjectOwned};
use seismic_attestation::{
    AttestationError, BackendAttestationError, DcapVerificationError, MaaError,
};
use std::fmt::Debug;
use tracing::{error, warn};

/// Terminal verdict on the requester's evidence: no identity the network can
/// appraise came out of it, so retrying with the same image cannot change the
/// answer. This code sends a joiner's operator to inspect its own attestation
/// stack, so only a failure attributed to the evidence is answered with it.
pub const ROOT_KEY_EVIDENCE_DENIED_CODE: i32 = -32001;
/// Terminal verdict on the requester's identity: its evidence verified and
/// yielded an admission ID the network does not accept. Nothing is wrong with
/// its attestation stack — this code sends a joiner's operator to launch a
/// guest whose admission ID the registry accepts.
pub const ROOT_KEY_IDENTITY_DENIED_CODE: i32 = -32003;
/// The responder could not decide, because its own chain, registry read, or
/// collateral infrastructure produced no usable answer. The requester's
/// evidence is not what failed: worth retrying — against another peer, or this
/// responder later.
pub const ROOT_KEY_ADMISSION_UNAVAILABLE_CODE: i32 = -32002;

pub(crate) fn invalid_root_key_request_rpc_error(error: impl Debug) -> ErrorObjectOwned {
    warn!(?error, "invalid root-key request");
    ErrorObjectOwned::owned(
        ErrorCode::InvalidParams.code(),
        "Invalid root-key request",
        None::<()>,
    )
}

pub(crate) fn internal_rpc_error(operation: &'static str, error: impl Debug) -> ErrorObjectOwned {
    error!(?error, operation, "RPC operation failed");
    ErrorObjectOwned::owned(
        ErrorCode::InternalError.code(),
        "Internal error",
        None::<()>,
    )
}

pub(crate) fn root_key_evidence_denied_rpc_error(error: impl Debug) -> ErrorObjectOwned {
    warn!(?error, "root-key evidence denied");
    ErrorObjectOwned::owned(
        ROOT_KEY_EVIDENCE_DENIED_CODE,
        "Root-key evidence denied",
        None::<()>,
    )
}

pub(crate) fn root_key_identity_denied_rpc_error(error: impl Debug) -> ErrorObjectOwned {
    warn!(?error, "root-key admission identity denied");
    ErrorObjectOwned::owned(
        ROOT_KEY_IDENTITY_DENIED_CODE,
        "Root-key admission identity denied",
        None::<()>,
    )
}

pub(crate) fn root_key_admission_unavailable_rpc_error(error: impl Debug) -> ErrorObjectOwned {
    warn!(?error, "root-key admission temporarily unavailable");
    ErrorObjectOwned::owned(
        ROOT_KEY_ADMISSION_UNAVAILABLE_CODE,
        "Root-key admission temporarily unavailable",
        None::<()>,
    )
}

/// Route a failed root-key answer to its wire error, by what the failure says
/// about the two parties (see [`DenialKind`]). Each code carries one move: fix
/// your attestation stack, get your identity accepted, or ask someone else. The
/// message is a stable constant either way; failure detail stays in the
/// responder's log.
///
/// A failure neither party can be held to answers as an internal error, the
/// same code this service already returns when its own custodian call fails.
/// Both denials are terminal — a joiner's operator reads them as *your*
/// configuration is wrong — so a responder that cannot attribute its own
/// failure must not reach for one: it would be telling a healthy joiner to stop
/// asking on no evidence at all, the very thing the attribution below exists to
/// prevent. Unattributed means neither side is blamed, and the joiner's move is
/// the same as for an unavailable responder: another peer.
pub(crate) fn root_key_answer_rpc_error(error: AnswerError) -> ErrorObjectOwned {
    match answer_failure_kind(&error) {
        Some(DenialKind::ResponderMisconfigured | DenialKind::ResponderTransient) => {
            root_key_admission_unavailable_rpc_error(error)
        }
        Some(DenialKind::RequesterIdentityNotAccepted) => root_key_identity_denied_rpc_error(error),
        Some(DenialKind::RequesterEvidenceUnusable) => root_key_evidence_denied_rpc_error(error),
        None => internal_rpc_error("answering the root-key request", error),
    }
}

/// What a failed answer says about the two parties. One arm per handshake step,
/// so a verdict can only come from the step that actually appraised the
/// requester; everything the responder does for itself blames nobody.
fn answer_failure_kind(error: &AnswerError) -> Option<DenialKind> {
    match error {
        AnswerError::VerifyRequester { source } => verification_failure_kind(source),
        AnswerError::WrapRootKey { .. }
        | AnswerError::ResponderEphemeralKey { .. }
        | AnswerError::GenerateResponderEvidence { .. } => None,
    }
}

/// Attribute a failure of verifying the requester's evidence.
fn verification_failure_kind(error: &AttestationError) -> Option<DenialKind> {
    match error {
        // The predicate's denial is typed, but it travels boxed: predicates are
        // caller-owned, so `AdmissionPredicate` cannot name their error. This is
        // the one place a downcast is the only way through, and a denial that is
        // not ours is one we cannot classify.
        AttestationError::AdmissionDenied(denial) => {
            Some(denial.downcast_ref::<AdmissionDenial>()?.kind())
        }
        AttestationError::Backend(backend) => backend_failure_kind(backend),
        // This service's own policy document and the backend's measurement
        // output: neither party's problem, and no verdict either way.
        AttestationError::PolicyFormat(_)
        | AttestationError::MissingMeasurements { .. }
        | AttestationError::MeasurementTypeMismatch { .. } => None,
    }
}

/// Attribute a backend verification failure, descending into the enum. The
/// backend mixes both parties: most of it is pure computation over the bytes the
/// requester supplied, but collateral fetching is the responder's own
/// infrastructure. A responder whose PCCS is unreachable, or one deployed
/// without one, must not answer a healthy joiner with a terminal verdict.
///
/// The enum is upstream's and can grow, so both sides are named explicitly and
/// anything else stays unattributed: an upstream bump can only ever widen the
/// unattributed set, never silently move a caller onto a verdict. Two variants
/// need a descent of their own — the Azure verifier funnels every Azure TDX
/// outcome through `MaaError`, and the DCAP layer reports a collateral-cache
/// failure a further level down.
fn backend_failure_kind(backend: &BackendAttestationError) -> Option<DenialKind> {
    match backend {
        // Collateral could not be fetched, its cache erred, or the attestation
        // provider did: nothing here appraised the requester's evidence.
        BackendAttestationError::Reqwest(_)
        | BackendAttestationError::Pccs(_)
        | BackendAttestationError::AttestationProvider(_)
        | BackendAttestationError::Maa(
            MaaError::Reqwest(_) | MaaError::DcapVerification(DcapVerificationError::Pccs(_)),
        ) => Some(DenialKind::ResponderTransient),
        // Deployed without a collateral source, pointed at a provider URL it
        // cannot use, or unable to read its own platform metadata.
        BackendAttestationError::NoPccs
        | BackendAttestationError::AttestationProviderUrl(_)
        | BackendAttestationError::PlatformMetadata(_) => Some(DenialKind::ResponderMisconfigured),
        // Offline appraisal of the evidence itself, whose verdict no collateral
        // source or configuration could change: the quote and its DCAP chain,
        // the vTPM quote and the AK certificate chain binding it, the transcript
        // binding recomputed from this responder's own view, and the shape of
        // the HCL report the identity has to be read out of.
        BackendAttestationError::NoCertificate
        | BackendAttestationError::X509Parse(_)
        | BackendAttestationError::X509(_)
        | BackendAttestationError::AttestationTypeNotAccepted
        | BackendAttestationError::AttestationGivenWhenNoneExpected
        | BackendAttestationError::DcapVerification(
            DcapVerificationError::DcapQvl(_)
            | DcapVerificationError::InputMismatch
            | DcapVerificationError::SgxNotSupported,
        )
        | BackendAttestationError::Maa(
            MaaError::DcapVerification(
                DcapVerificationError::DcapQvl(_)
                | DcapVerificationError::InputMismatch
                | DcapVerificationError::SgxNotSupported,
            )
            | MaaError::Hcl(_)
            | MaaError::AzureAttestationPayloadTooLarge { .. }
            | MaaError::TpmQuoteVerify(_)
            | MaaError::TdReportInputMismatch
            | MaaError::ClaimsUserDataInputMismatch
            | MaaError::ClaimsUserDataBadLength
            | MaaError::ClaimsMissingUserData
            | MaaError::ClaimsMissingHCLAkPub
            | MaaError::AkFromClaimsNotEqualAkFromHcl
            | MaaError::AkFromClaimsNotEqualAkFromCertificate
            | MaaError::WebPki(_)
            | MaaError::X509Parse(_)
            | MaaError::X509(_)
            | MaaError::Pem(_)
            | MaaError::NotRsa
            | MaaError::JwkParse
            | MaaError::JwkConversion
            | MaaError::CannotExtractMeasurementsFromQuote,
        ) => Some(DenialKind::RequesterEvidenceUnusable),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rpc_errors_expose_only_stable_messages() {
        let invalid = invalid_root_key_request_rpc_error("private parser detail");
        assert_eq!(invalid.code(), ErrorCode::InvalidParams.code());
        assert_eq!(invalid.message(), "Invalid root-key request");

        let denied = root_key_evidence_denied_rpc_error("private verifier detail");
        assert_eq!(denied.code(), ROOT_KEY_EVIDENCE_DENIED_CODE);
        assert_eq!(denied.message(), "Root-key evidence denied");

        let unavailable = root_key_admission_unavailable_rpc_error("private chain detail");
        assert_eq!(unavailable.code(), ROOT_KEY_ADMISSION_UNAVAILABLE_CODE);
        assert_eq!(
            unavailable.message(),
            "Root-key admission temporarily unavailable"
        );

        let identity = root_key_identity_denied_rpc_error("private admission ID");
        assert_eq!(identity.code(), ROOT_KEY_IDENTITY_DENIED_CODE);
        assert_eq!(identity.message(), "Root-key admission identity denied");

        let internal = internal_rpc_error("generating evidence", "private backend detail");
        assert_eq!(internal.code(), ErrorCode::InternalError.code());
        assert_eq!(internal.message(), "Internal error");

        for error in [invalid, denied, identity, unavailable, internal] {
            assert!(!error.to_string().contains("private"));
        }
    }

    /// A failure of the one step that appraises the requester.
    fn verify_error(source: AttestationError) -> AnswerError {
        AnswerError::VerifyRequester { source }
    }

    fn backend_error(backend: BackendAttestationError) -> AnswerError {
        verify_error(AttestationError::Backend(backend))
    }

    /// A denial the predicate raised, boxed the way `AdmissionPredicate`
    /// delivers it.
    fn denial_error(denial: AdmissionDenial) -> AnswerError {
        verify_error(AttestationError::AdmissionDenied(Box::new(denial)))
    }

    #[test]
    fn responder_chain_faults_map_to_unavailable() {
        let unavailable =
            root_key_answer_rpc_error(denial_error(AdmissionDenial::ChainRegressedToGenesis));
        assert_eq!(unavailable.code(), ROOT_KEY_ADMISSION_UNAVAILABLE_CODE);

        // A responder on the wrong chain is unavailable rather than denying,
        // even though waiting cannot fix it: the requester's move is to ask
        // another peer, and its evidence is not what failed.
        let wrong_chain =
            root_key_answer_rpc_error(denial_error(AdmissionDenial::ChainGenesisMismatch {
                expected: alloy_primitives::B256::repeat_byte(0xb0),
                found: alloy_primitives::B256::repeat_byte(0xef),
            }));
        assert_eq!(wrong_chain.code(), ROOT_KEY_ADMISSION_UNAVAILABLE_CODE);
    }

    /// The requester's two verdicts answer two different questions, so they
    /// travel on two different codes.
    #[test]
    fn requester_verdicts_split_evidence_from_identity() {
        let unusable = root_key_answer_rpc_error(denial_error(
            AdmissionDenial::UnsupportedAttestationType(seismic_attestation::AttestationType::None),
        ));
        assert_eq!(unusable.code(), ROOT_KEY_EVIDENCE_DENIED_CODE);

        let identity = root_key_answer_rpc_error(denial_error(
            AdmissionDenial::RegistryNotAccepted(alloy_primitives::B256::ZERO.into()),
        ));
        assert_eq!(identity.code(), ROOT_KEY_IDENTITY_DENIED_CODE);
    }

    /// A responder that cannot obtain collateral has appraised nothing, so it
    /// answers as unavailable — the joiner's move is another peer, not a new
    /// image.
    #[test]
    fn collateral_infrastructure_faults_map_to_unavailable() {
        let no_pccs = root_key_answer_rpc_error(backend_error(BackendAttestationError::NoPccs));
        assert_eq!(no_pccs.code(), ROOT_KEY_ADMISSION_UNAVAILABLE_CODE);

        let provider = root_key_answer_rpc_error(backend_error(
            BackendAttestationError::AttestationProvider("502 Bad Gateway".into()),
        ));
        assert_eq!(provider.code(), ROOT_KEY_ADMISSION_UNAVAILABLE_CODE);

        let provider_url = root_key_answer_rpc_error(backend_error(
            BackendAttestationError::AttestationProviderUrl("not a URL".into()),
        ));
        assert_eq!(provider_url.code(), ROOT_KEY_ADMISSION_UNAVAILABLE_CODE);
    }

    /// Offline appraisal of the evidence is the requester's to answer for, and
    /// the Azure funnel is where the production path reports it.
    #[test]
    fn offline_evidence_failures_are_denied_on_the_evidence() {
        let binding = root_key_answer_rpc_error(backend_error(BackendAttestationError::Maa(
            MaaError::TdReportInputMismatch,
        )));
        assert_eq!(binding.code(), ROOT_KEY_EVIDENCE_DENIED_CODE);

        let dcap = root_key_answer_rpc_error(backend_error(BackendAttestationError::Maa(
            MaaError::DcapVerification(DcapVerificationError::InputMismatch),
        )));
        assert_eq!(dcap.code(), ROOT_KEY_EVIDENCE_DENIED_CODE);

        let no_certificate =
            root_key_answer_rpc_error(backend_error(BackendAttestationError::NoCertificate));
        assert_eq!(no_certificate.code(), ROOT_KEY_EVIDENCE_DENIED_CODE);
    }

    /// Neither denial is reachable by omission. A failure this responder cannot
    /// pin on either party blames nobody: a terminal verdict would tell a
    /// healthy joiner to stop asking on no evidence at all.
    #[test]
    fn unattributed_failures_blame_neither_party() {
        let unnamed_backend = root_key_answer_rpc_error(backend_error(
            BackendAttestationError::MeasurementsNotAccepted,
        ));
        assert_eq!(
            unnamed_backend.code(),
            ErrorCode::InternalError.code(),
            "an unnamed backend variant must not reach a verdict"
        );

        let own_plumbing =
            root_key_answer_rpc_error(verify_error(AttestationError::MissingMeasurements {
                attestation_type: seismic_attestation::AttestationType::AzureTdx,
            }));
        assert_eq!(own_plumbing.code(), ErrorCode::InternalError.code());

        let custodian = root_key_answer_rpc_error(AnswerError::WrapRootKey {
            source: seismic_custodian_ipc::IpcError::Denied("WrapRootKey".into()),
        });
        assert_eq!(custodian.code(), ErrorCode::InternalError.code());
    }

    /// The step is what attributes, not the error inside it: the very variant
    /// that makes a *verification* failure the responder's collateral problem
    /// says nothing about either party when this responder was minting its own
    /// evidence.
    #[test]
    fn the_same_backend_error_attributes_by_step() {
        let verifying = root_key_answer_rpc_error(backend_error(BackendAttestationError::NoPccs));
        assert_eq!(verifying.code(), ROOT_KEY_ADMISSION_UNAVAILABLE_CODE);

        let generating = root_key_answer_rpc_error(AnswerError::GenerateResponderEvidence {
            source: AttestationError::Backend(BackendAttestationError::NoPccs),
        });
        assert_eq!(generating.code(), ErrorCode::InternalError.code());
    }
}
