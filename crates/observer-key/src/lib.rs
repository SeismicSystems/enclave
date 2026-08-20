//! Observer-key derivation for the centralized custodian.
//!
//! A summit observer is a non-validator identity additively derived from a
//! validator's master ed25519 node key: only the master-key holder can sign
//! as any child, while anyone holding the master *public* key can derive the
//! matching child public key from public data alone. The custodian uses this
//! to authenticate an observer custodian to its parent: the observer signs
//! fetch requests with a derived child signer, and the parent verifies
//! against `derive_child_public` of its own node key.
//!
//! [`derive`] is a byte-exact port of summit's `types/src/ext_private_key.rs`
//! — same domain tags, same `m/seismic/observer/{index}` path, same tweak
//! construction — pinned by golden vectors generated from summit's code (see
//! the tests). The one deliberate difference: [`ObserverSigner::sign`] signs
//! the raw message, without commonware's `union_unique` framing; custodian
//! callers build their own domain-separated payloads.
//!
//! The derivation `namespace` used by the custodian comes from
//! [`observer_namespace_from_chain_id`], not summit's genesis-digest chain
//! domain (which a custodian cannot compute). Custodian observer identities
//! are therefore distinct from the node's P2P observer identities even for
//! the same master key and index — deliberate key-separation between the two
//! protocols.

mod derive;
mod keystore;
mod namespace;

pub use derive::{
    DeriveError, ObserverSigner, derive_child_public, master_public_from_seed, verify,
};
pub use keystore::load_node_seed;
pub use namespace::observer_namespace_from_chain_id;
