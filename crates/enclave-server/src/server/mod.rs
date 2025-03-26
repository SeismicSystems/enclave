pub mod server;
mod internal;
// mod operator;
mod public;

use internal::EnclaveInternalHandle;
use public::EnclavePublicHandle;

/// Contains the handles to the spawned RPC servers.
///
/// This can be used to access the endpoints of the servers.
#[derive(Debug, Clone)]
pub struct EnclaveRpcServerHandles {
    pub public: EnclavePublicHandle,
    pub internal: EnclaveInternalHandle,
    // pub operator: EnclaveOperatorHandle,
}