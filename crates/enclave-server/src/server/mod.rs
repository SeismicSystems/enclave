//! Configure Enclave RPC.

pub mod server;

mod internal;
// mod operator;
mod public;

use crate::server::internal::{
    EnclaveInternalRPCModule, EnclaveInternalServer, EnclaveInternalServerConfig,
};
use crate::server::public::{
    EnclavePublicRPCModule, EnclavePublicServer, EnclavePublicServerConfig,
};
use internal::EnclaveInternalHandle;
use public::EnclavePublicHandle;

use reth_rpc_layer::JwtSecret;

/// Contains the handles to the spawned RPC servers.
///
/// This can be used to access the endpoints of the servers.
#[derive(Debug, Clone)]
pub struct EnclaveRpcServerHandles {
    pub public: EnclavePublicHandle,
    pub internal: EnclaveInternalHandle,
    // pub operator: EnclaveOperatorHandle,
}
impl EnclaveRpcServerHandles {
    pub fn stop(&self) {
        self.public.stop();
        self.internal.stop();
    }
    pub fn stopped(&self) {
        self.public.is_stopped();
        self.internal.is_stopped();
    }
}

pub struct EnclaveRpcModuleConfig {}
pub struct EncalveModuleBuilder {}
pub struct EnclaveRpcModule {}
pub struct EnclaveRpcServerConfig {}

// async fn sketch() {
//     let modules_config = EnclaveRpcModuleConfig::default().with_http(vec![
//         // something here
//     ]);
//     let modules = EncalveModuleBuilder::new().build(modules_config);
//     let handle = EnclaveRpcServerConfig::default()
//         .with_http(ServerBuilder::default())
//         .start(&modules)
//         .await;
// }

async fn build_default() -> Result<EnclaveRpcServerHandles, anyhow::Error> {
    let my_internal_module = EnclaveInternalRPCModule::new(EnclaveInternalServer::new());
    let my_internal_server_config =
        EnclaveInternalServerConfig::new_from_jwt_secret(JwtSecret::random());
    let my_internal_handle = my_internal_server_config.start(my_internal_module).await?;

    let my_public_module = EnclavePublicRPCModule::new(EnclavePublicServer::new());
    let my_public_server_config = EnclavePublicServerConfig::default();
    let my_public_handle = my_public_server_config.start(my_public_module).await?;

    let handle_struct = EnclaveRpcServerHandles {
        public: my_public_handle,
        internal: my_internal_handle,
    };

    Ok(handle_struct)
}
