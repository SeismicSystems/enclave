// functions that should only be accessible by components inside the enclave
// e.g. reth
pub mod internal;

// functions that should be accessible only by the node operator
pub mod operator;

// functions that may be freely accessible without authentication
pub mod public;
