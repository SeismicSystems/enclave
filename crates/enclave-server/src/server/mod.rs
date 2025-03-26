pub mod server;
mod internal;

use internal::EnclaveInternalHandle;

/// Contains the handles to the spawned RPC servers.
///
/// This can be used to access the endpoints of the servers.
#[derive(Debug, Clone)]
pub struct EnclaveRpcServerHandles {
    // pub public: PublicServerHandle,
    pub internal: EnclaveInternalHandle,
    // pub operator: OperatorServerHandle,
}