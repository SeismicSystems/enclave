pub mod api;
pub mod mock;

pub use api::*;
pub use secp256k1;
// Compatibility re-export: the crypto helpers moved to their own crate so key
// custody code can use them without pulling in this crate's JSON-RPC surface.
// Existing users (seismic-reth) keep importing them from here unchanged.
//
// TODO: This facade is temporary. The plan is to split this crate and
// enclave-server into small single-purpose crates (RPC types, crypto helpers,
// mock server, key-custodian client) that seismic-reth imports individually;
// once reth is updated to do so, this re-export goes away.
pub use seismic_enclave_crypto::*;
