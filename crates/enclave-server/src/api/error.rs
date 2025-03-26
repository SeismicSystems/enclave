// Error type for RPC operations
pub type RpcResult<T> = Result<T, RpcError>;

/// Common error type for RPC operations
#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    #[error("Invalid argument: {0}")]
    BadArgument(#[from] anyhow::Error),
    
    #[error("Invalid ciphertext: {0}")]
    InvalidCiphertext(anyhow::Error),
    
    #[error("Internal error: {0}")]
    Internal(anyhow::Error),
    
    // Add other error variants as needed
}

/// Helper functions for error construction
pub fn rpc_bad_argument_error<E: Into<anyhow::Error>>(error: E) -> RpcError {
    RpcError::BadArgument(error.into())
}

pub fn rpc_invalid_ciphertext_error<E: Into<anyhow::Error>>(error: E) -> RpcError {
    RpcError::InvalidCiphertext(error.into())
}

