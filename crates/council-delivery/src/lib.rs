//! Wire types, binding digests, and envelope crypto for security-council
//! epoch-key deliveries to the centralized custodian.
//!
//! One envelope carries one 32-byte purpose key for one `(purpose, epoch)`
//! pair: AEAD-encrypted to the custodian's inbox keypair and signed by the
//! council key over a domain-separated digest of the complete payload
//! ([`bindings`]). Envelopes are self-contained — verification needs only the
//! council pubkey, the network id, and the inbox key — so the custodian
//! persists them verbatim and replays verification on every boot.
//!
//! Boundary rule: this crate is a leaf shared between the custodian host and
//! off-node council signer tooling. No custodian, attestation, or async
//! dependencies; epoch sequencing and conflict policy belong to the host.

mod bindings;
mod envelope;
mod messages;

pub use bindings::{
    delivery_binding, delivery_context_binding, payload_binding, payload_context_binding,
};
pub use envelope::{
    EphemeralKeypair, OpenDeliveryError, canonical_envelope_bytes, envelope_from_bytes,
    open_delivery, seal_delivery,
};
pub use messages::{
    CouncilRequest, CouncilResponse, CouncilStatus, DeliveryPayload, DeliveryPurpose, InboxPk,
    RejectCode, SignedDeliveryEnvelope,
};
