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

/// A refused root-key answer, in the one type both sides of the handshake
/// hold it in: the responder builds its wire error from a value of this type,
/// and the joiner reads one back out of the code that arrives.
///
/// This is [`DenialKind`] as a stranger may see it. It keeps that same split by
/// party, and collapses the responder's own half — a peer that is
/// misconfigured and one that is merely lagging leave a requester the same
/// move, and which of the two it is belongs in that peer's log, not in an
/// answer to an unauthenticated caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootKeyRefusal {
    /// Terminal verdict on the requester's evidence: no identity the network
    /// can appraise came out of it, so retrying with the same image cannot
    /// change the answer. It sends a joiner's operator to inspect its own
    /// attestation stack, so only a failure attributed to the evidence is
    /// answered with it.
    RequesterEvidenceUnusable,
    /// Terminal verdict on the requester's identity: its evidence verified and
    /// yielded an admission ID the network does not accept. Nothing is wrong
    /// with its attestation stack — this sends a joiner's operator to launch a
    /// guest whose admission ID the registry accepts.
    RequesterIdentityNotAccepted,
    /// The responder could not decide, because its own chain, registry read, or
    /// collateral infrastructure produced no usable answer. The requester's
    /// evidence is not what failed: worth retrying — against another peer, or
    /// this responder later.
    ResponderUnavailable,
}

impl RootKeyRefusal {
    /// Every refusal this contract defines. [`Self::from_code`] reads this
    /// list, so a variant left out of it is one no joiner can read back.
    const ALL: [Self; 3] = [
        Self::RequesterEvidenceUnusable,
        Self::RequesterIdentityNotAccepted,
        Self::ResponderUnavailable,
    ];

    /// The JSON-RPC error code this refusal travels as. The three run in the
    /// order the handshake reaches them: what the requester's evidence
    /// yielded, then whether that identity is accepted, then whether this
    /// responder could decide at all.
    pub const fn code(self) -> i32 {
        match self {
            Self::RequesterEvidenceUnusable => -32001,
            Self::RequesterIdentityNotAccepted => -32002,
            Self::ResponderUnavailable => -32003,
        }
    }

    /// The message that travels with it: a stable constant, so an
    /// unauthenticated caller learns the outcome and nothing about why. Paired
    /// with the code here, where the two cannot drift apart.
    pub const fn message(self) -> &'static str {
        match self {
            Self::RequesterEvidenceUnusable => "Root-key evidence denied",
            Self::RequesterIdentityNotAccepted => "Root-key admission identity denied",
            Self::ResponderUnavailable => "Root-key admission temporarily unavailable",
        }
    }

    /// Read a refusal back off a JSON-RPC error code.
    ///
    /// `None` for every other code — an internal error, an invalid request, or
    /// a code this service does not define. Those leave the requester exactly
    /// where an unattributed failure does: nothing said about it, and the same
    /// move as for an unavailable responder.
    pub fn from_code(code: i32) -> Option<Self> {
        Self::ALL.into_iter().find(|refusal| refusal.code() == code)
    }
}

impl From<DenialKind> for RootKeyRefusal {
    fn from(kind: DenialKind) -> Self {
        match kind {
            DenialKind::RequesterEvidenceUnusable => Self::RequesterEvidenceUnusable,
            DenialKind::RequesterIdentityNotAccepted => Self::RequesterIdentityNotAccepted,
            DenialKind::ResponderMisconfigured | DenialKind::ResponderTransient => {
                Self::ResponderUnavailable
            }
        }
    }
}

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

/// Answer with `refusal`, keeping the detail that produced it in this
/// responder's log.
fn refusal_rpc_error(refusal: RootKeyRefusal, error: impl Debug) -> ErrorObjectOwned {
    warn!(?error, ?refusal, "refusing the root-key request");
    ErrorObjectOwned::owned(refusal.code(), refusal.message(), None::<()>)
}

/// Route a failed root-key answer to its wire error, by what the failure says
/// about the two parties (see [`DenialKind`]). Each refusal carries one move:
/// fix your attestation stack, get your identity accepted, or ask someone else.
/// The message is a stable constant either way; failure detail stays in the
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
    match answer_failure_kind(&error).map(RootKeyRefusal::from) {
        Some(refusal) => refusal_rpc_error(refusal, error),
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
        // The requester sent evidence that attests nothing, so no identity
        // came out of it. Same verdict as a quote that fails to verify: its
        // operator fixes the attestation stack, and the network never saw an
        // identity to accept or reject.
        AttestationError::Unattested => Some(DenialKind::RequesterEvidenceUnusable),
        // This service's own policy document and the backend's measurement
        // output: neither party's problem, and no verdict either way.
        AttestationError::PolicyFormat(_) | AttestationError::MeasurementTypeMismatch { .. } => {
            None
        }
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

    /// The numbers and messages a peer of any version reads. Pinned as
    /// literals: this is the wire, so changing one has to be a deliberate edit
    /// to this list, not a side effect of renaming a variant.
    #[test]
    fn the_wire_form_of_every_refusal_is_fixed() {
        let wire = [
            (
                RootKeyRefusal::RequesterEvidenceUnusable,
                -32001,
                "Root-key evidence denied",
            ),
            (
                RootKeyRefusal::RequesterIdentityNotAccepted,
                -32002,
                "Root-key admission identity denied",
            ),
            (
                RootKeyRefusal::ResponderUnavailable,
                -32003,
                "Root-key admission temporarily unavailable",
            ),
        ];

        assert_eq!(
            wire.len(),
            RootKeyRefusal::ALL.len(),
            "a refusal the contract defines is missing its wire form here"
        );
        for (refusal, code, message) in wire {
            assert_eq!(refusal.code(), code);
            assert_eq!(refusal.message(), message);
            assert_eq!(RootKeyRefusal::from_code(code), Some(refusal));
        }
        assert_eq!(
            RootKeyRefusal::from_code(ErrorCode::InternalError.code()),
            None
        );
    }

    #[test]
    fn rpc_errors_expose_only_stable_messages() {
        let invalid = invalid_root_key_request_rpc_error("private parser detail");
        assert_eq!(invalid.code(), ErrorCode::InvalidParams.code());
        assert_eq!(invalid.message(), "Invalid root-key request");

        let internal = internal_rpc_error("generating evidence", "private backend detail");
        assert_eq!(internal.code(), ErrorCode::InternalError.code());
        assert_eq!(internal.message(), "Internal error");

        let refused =
            RootKeyRefusal::ALL.map(|refusal| refusal_rpc_error(refusal, "private denial detail"));
        for (error, refusal) in refused.iter().zip(RootKeyRefusal::ALL) {
            assert_eq!(error.code(), refusal.code());
            assert_eq!(error.message(), refusal.message());
        }

        for error in refused.into_iter().chain([invalid, internal]) {
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

    /// What a joiner takes away from a failed answer: the responder's error
    /// put on the wire and read back off it, so every case below asserts on
    /// the round trip rather than on a number.
    fn refusal_of(error: AnswerError) -> Option<RootKeyRefusal> {
        RootKeyRefusal::from_code(root_key_answer_rpc_error(error).code())
    }

    #[test]
    fn responder_chain_faults_map_to_unavailable() {
        assert_eq!(
            refusal_of(denial_error(AdmissionDenial::ChainRegressedToGenesis)),
            Some(RootKeyRefusal::ResponderUnavailable)
        );

        // A responder on the wrong chain is unavailable rather than denying,
        // even though waiting cannot fix it: the requester's move is to ask
        // another peer, and its evidence is not what failed.
        assert_eq!(
            refusal_of(denial_error(AdmissionDenial::ChainGenesisMismatch {
                expected: alloy_primitives::B256::repeat_byte(0xb0),
                found: alloy_primitives::B256::repeat_byte(0xef),
            })),
            Some(RootKeyRefusal::ResponderUnavailable)
        );
    }

    /// The requester's two verdicts answer two different questions, so they
    /// travel as two different refusals.
    #[test]
    fn requester_verdicts_split_evidence_from_identity() {
        assert_eq!(
            refusal_of(denial_error(AdmissionDenial::UnsupportedAttestationType(
                seismic_attestation::AttestationType::DcapTdx
            ))),
            Some(RootKeyRefusal::RequesterEvidenceUnusable)
        );
        assert_eq!(
            refusal_of(verify_error(AttestationError::Unattested)),
            Some(RootKeyRefusal::RequesterEvidenceUnusable)
        );

        assert_eq!(
            refusal_of(denial_error(AdmissionDenial::RegistryNotAccepted(
                alloy_primitives::B256::ZERO.into()
            ))),
            Some(RootKeyRefusal::RequesterIdentityNotAccepted)
        );
    }

    /// A responder that cannot obtain collateral has appraised nothing, so it
    /// answers as unavailable — the joiner's move is another peer, not a new
    /// image.
    #[test]
    fn collateral_infrastructure_faults_map_to_unavailable() {
        let faults = [
            BackendAttestationError::NoPccs,
            BackendAttestationError::AttestationProvider("502 Bad Gateway".into()),
            BackendAttestationError::AttestationProviderUrl("not a URL".into()),
        ];

        for fault in faults {
            assert_eq!(
                refusal_of(backend_error(fault)),
                Some(RootKeyRefusal::ResponderUnavailable)
            );
        }
    }

    /// Offline appraisal of the evidence is the requester's to answer for, and
    /// the Azure funnel is where the production path reports it.
    #[test]
    fn offline_evidence_failures_are_denied_on_the_evidence() {
        let failures = [
            BackendAttestationError::Maa(MaaError::TdReportInputMismatch),
            BackendAttestationError::Maa(MaaError::DcapVerification(
                DcapVerificationError::InputMismatch,
            )),
            BackendAttestationError::NoCertificate,
        ];

        for failure in failures {
            assert_eq!(
                refusal_of(backend_error(failure)),
                Some(RootKeyRefusal::RequesterEvidenceUnusable)
            );
        }
    }

    /// Neither denial is reachable by omission. A failure this responder cannot
    /// pin on either party blames nobody: a terminal verdict would tell a
    /// healthy joiner to stop asking on no evidence at all.
    #[test]
    fn unattributed_failures_blame_neither_party() {
        let unattributed = [
            // An unnamed backend variant must not reach a verdict.
            backend_error(BackendAttestationError::MeasurementsNotAccepted),
            // This responder's own plumbing.
            verify_error(AttestationError::MeasurementTypeMismatch {
                attestation_type: seismic_attestation::AttestationType::AzureTdx,
                measurements: Box::new(seismic_attestation::MultiMeasurements::NoAttestation),
            }),
            AnswerError::WrapRootKey {
                source: seismic_custodian_ipc::IpcError::Denied("WrapRootKey".into()),
            },
        ];

        for error in unattributed {
            let answer = root_key_answer_rpc_error(error);
            assert_eq!(answer.code(), ErrorCode::InternalError.code());
            assert_eq!(
                RootKeyRefusal::from_code(answer.code()),
                None,
                "an unattributed failure must not arrive as a refusal"
            );
        }
    }

    /// The step is what attributes, not the error inside it: the very variant
    /// that makes a *verification* failure the responder's collateral problem
    /// says nothing about either party when this responder was minting its own
    /// evidence.
    #[test]
    fn the_same_backend_error_attributes_by_step() {
        assert_eq!(
            refusal_of(backend_error(BackendAttestationError::NoPccs)),
            Some(RootKeyRefusal::ResponderUnavailable)
        );

        let generating = root_key_answer_rpc_error(AnswerError::GenerateResponderEvidence {
            source: AttestationError::Backend(BackendAttestationError::NoPccs),
        });
        assert_eq!(generating.code(), ErrorCode::InternalError.code());
    }
}
