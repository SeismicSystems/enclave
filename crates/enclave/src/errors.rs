//! Utility functions for converting errors into JSON-RPC error responses

use anyhow::Error;

/// JSON-RPC custom error code representing a conflict due to uninitialized resource
pub const CONFLICT_CODE: i32 = -32409;

/// Convert a bad evidence error into a JSON-RPC error response
pub fn rpc_bad_evidence_error(e: Error) -> jsonrpsee::types::ErrorObjectOwned {
    jsonrpsee::types::ErrorObject::owned(
        jsonrpsee::types::error::INVALID_PARAMS_CODE,
        format!("Error while evaluating evidence: {:?}", e),
        None::<()>,
    )
}

/// Convert a bad attestation error into a JSON-RPC error response
pub fn rpc_bad_quote_error(e: Error) -> jsonrpsee::types::ErrorObjectOwned {
    jsonrpsee::types::ErrorObject::owned(
        jsonrpsee::types::error::INVALID_PARAMS_CODE,
        format!("Error while generating a quote: {:?}", e),
        None::<()>,
    )
}

/// Convert a bad genesis error into a JSON-RPC error response
pub fn rpc_bad_genesis_error(e: Error) -> jsonrpsee::types::ErrorObjectOwned {
    jsonrpsee::types::ErrorObject::owned(
        jsonrpsee::types::error::INVALID_PARAMS_CODE,
        format!("Error while generating a genesis attestation: {:?}", e),
        None::<()>,
    )
}

/// Convert a bad argument error into a JSON-RPC error response
pub fn rpc_bad_argument_error(e: Error) -> jsonrpsee::types::ErrorObjectOwned {
    jsonrpsee::types::ErrorObject::owned(
        jsonrpsee::types::error::INVALID_PARAMS_CODE,
        format!("Invalid Argument: {:?}", e),
        None::<()>,
    )
}

// Convert a generic error into a JSON-RPC error response
pub fn rpc_internal_server_error(e: Error) -> jsonrpsee::types::ErrorObjectOwned {
    jsonrpsee::types::ErrorObject::owned(
        jsonrpsee::types::error::INTERNAL_ERROR_CODE,
        format!("Internal server error: {}", e),
        None::<()>,
    )
}

/// Convert an invalid ciphertext error into a JSON-RPC error response
pub fn rpc_invalid_ciphertext_error(e: Error) -> jsonrpsee::types::ErrorObjectOwned {
    jsonrpsee::types::ErrorObject::owned(
        jsonrpsee::types::error::INVALID_PARAMS_CODE,
        format!("Invalid ciphertext: {}", e),
        None::<()>,
    )
}

/// Convert an uninitialized resource error into a JSON-RPC error response
pub fn rpc_conflict_error(e: Error) -> jsonrpsee::types::ErrorObjectOwned {
    jsonrpsee::types::ErrorObject::owned(
        CONFLICT_CODE,
        format!("Request conflicts with current state: {}", e),
        None::<()>,
    )
}
