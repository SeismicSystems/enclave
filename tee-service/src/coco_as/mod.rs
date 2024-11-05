pub mod handlers;
pub mod policies;

/// Handles converting between the API and the original enums
/// This is necessary because if you import the original enums directly
/// in the API crate, it tries to build the entire attestation service crate,
/// which can break external projects
pub mod into_original;
