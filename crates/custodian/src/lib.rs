//! The Seismic network root-key custodian.
//!
//! [`Custodian`] owns `root_key`, the network-wide master secret from which
//! every purpose key is derived (tx-io, snapshot, RNG, LUKS storage +
//! header-MAC). The key is RAM-only: generated fresh on the genesis node or
//! received from a peer via the attested wrap protocol, never written to disk
//! in any form. At-rest confidentiality comes from the LUKS volume, whose
//! unlock key is itself derived from `root_key`.
//!
//! Boundary rule: this crate never sees remote attestation evidence, let
//! alone parses it. Releasing `root_key` to a peer requires a
//! [`VerifiedPeerAuthorization`], produced by a caller that has already
//! verified the peer's evidence against admission policy. Keeping the
//! CVE-prone evidence parsers (DCAP, vTPM, X.509) and every network listener
//! out of this crate is what lets the process holding `root_key` shrink to a
//! minimal, auditable surface.

// One module per way key material can leave the process:
mod custodian; // it doesn't — RAM-only derivation of root_key + purpose keys
mod luks_keyfile; // ephemeral tmpfs keyfile, handed off to setup-persistent-luks
mod root_key_wrap; // over the network, AEAD-wrapped to an attested peer

pub use custodian::{Custodian, Key, KeyPurpose};
pub use root_key_wrap::{
    EphemeralKeypair, VerifiedPeerAuthorization, WrappedRootKey, unwrap_root_key,
};
