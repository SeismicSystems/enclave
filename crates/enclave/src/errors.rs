use anyhow::Error;

/// Convert a bad evidence error into a JSON-RPC error response
pub fn rpc_bad_evidence_error(e: Error) -> jsonrpsee::types::ErrorObjectOwned {
    jsonrpsee::types::ErrorObject::owned(
        jsonrpsee::types::error::INVALID_PARAMS_CODE,
        format!("Error while evaluating evidence: {:?}", e),
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

// convert a missing snapshot error into a JSON-RPC error response
pub fn rpc_missing_snapshot_error() -> jsonrpsee::types::ErrorObjectOwned {
    jsonrpsee::types::ErrorObject::owned(
        jsonrpsee::types::error::INVALID_PARAMS_CODE,
        "Snapshot file not found. Snapshot must be prepared/uploaded before attempting this action.",
        None::<()>,
    )
}
