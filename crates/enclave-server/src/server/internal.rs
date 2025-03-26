use anyhow::Result;
use jsonrpsee::core::async_trait;
use jsonrpsee::core::RpcResult;
use jsonrpsee::server::ServerBuilder;
use jsonrpsee::{
    http_client::transport::HttpBackend,
    server::{AlreadyStoppedError, RpcModule},
};
use reth_rpc_layer::AuthClientLayer;
use reth_rpc_layer::AuthClientService;
use reth_rpc_layer::JwtSecret;
use std::net::SocketAddr;
use tracing::debug;
use tower::layer::util::Identity;
use reth_rpc_layer::JwtAuthValidator;
use reth_rpc_layer::AuthLayer;

use seismic_enclave::key_stuff::internal::EnclaveInternalAPIServer;
use seismic_enclave::tx_io::{
    IoDecryptionRequest, IoDecryptionResponse,
};
use crate::key_manager::key_manager::KeyManager;
use crate::tx_io::handlers::tx_io_decrypt_handler;


// Implements the EnclaveInternalAPIServer trait, i.e. the expected endpoints
pub struct EnclaveInternalServer {
    key_manager: KeyManager,
}
#[async_trait]
impl EnclaveInternalAPIServer for EnclaveInternalServer {
    /// Handler for: `decrypt`
    async fn decrypt(&self, req: IoDecryptionRequest) -> RpcResult<IoDecryptionResponse> {
        debug!(target: "rpc::enclave", "Serving decrypt");
        tx_io_decrypt_handler(req, &self.key_manager).await
    }
}

// The RPC module for the enclave internal server
// Takes in the EnclaveInternalAPIServer trait converts it 
// to a generic RPC module so that it can be grouped with other RPC modules
// With a EnclaveInternalServerConfig, defines a convenience function for starting the server
pub struct EnclaveInternalRPCModule {
   inner: RpcModule<()>
}
impl EnclaveInternalRPCModule {
    pub fn new<EnclaveInternalServer>(internal_server: EnclaveInternalServer) -> Self 
    where EnclaveInternalServer: EnclaveInternalAPIServer
    {
        let mut module = RpcModule::new(());
        module.merge(internal_server.into_rpc()).expect("No conflicting methods");
        Self { inner: module }
    }

    /// Get a reference to the inner `RpcModule`.
    pub fn module_mut(&mut self) -> &mut RpcModule<()> {
        &mut self.inner
    }

    /// Convenience function for starting a server
    pub async fn start_server(
        self,
        config: EnclaveInternalServerConfig,
    ) -> Result<EnclaveInternalHandle, anyhow::Error> {
        config.start(self).await
    }
}

/// EnclaveInternalServerConfig is a configuration for a enclave internal RPC server
/// It defines the parts of the server that are unrelated to the API,
/// i.e. ports, auth, middlewares, etc.
/// With a EnclaveInternalRPCModule, defines a convenience function for starting the server
pub struct EnclaveInternalServerConfig {
    /// Where the server should listen.
    pub(crate) socket_addr: SocketAddr,
    /// The secret for the auth layer of the server.
    pub(crate) secret: JwtSecret,
    /// Configs for JSON-RPC Http.
    pub(crate) server_config: ServerBuilder<Identity, Identity>,
}
impl EnclaveInternalServerConfig {
    /// Returns the address the server will listen on.
    pub const fn address(&self) -> SocketAddr {
        self.socket_addr
    }

    /// Convenience function to start a server in one step.
    pub async fn start(self, module: EnclaveInternalRPCModule) -> Result<EnclaveInternalHandle, anyhow::Error> {
        let Self { socket_addr, secret, server_config,} = self;

        // Create auth middleware.
        let middleware =
            tower::ServiceBuilder::new().layer(AuthLayer::new(JwtAuthValidator::new(secret)));

        // By default, both http and ws are enabled.
        let server = server_config
            .set_http_middleware(middleware)
            .build(socket_addr)
            .await?;

        let local_addr = server
            .local_addr()?;

        let handle = server.start(module.inner.clone());

        Ok(EnclaveInternalHandle { handle, local_addr, secret})
    }
}



// EnclaveInternalHandle is a handle for a spawned enclave internal RPC server
#[derive(Debug, Clone)]
pub struct EnclaveInternalHandle {
    local_addr: SocketAddr,
    handle: jsonrpsee::server::ServerHandle,
    secret: JwtSecret,
}

impl EnclaveInternalHandle {
    /// Returns the [`SocketAddr`] of the http server if started.
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Tell the server to stop without waiting for the server to stop.
    pub fn stop(self) -> Result<(), AlreadyStoppedError> {
        self.handle.stop()
    }

    /// Returns the url to the http server
    pub fn http_url(&self) -> String {
        format!("http://{}", self.local_addr)
    }

    /// Returns a http client connected to the server.
    pub fn http_client(
        &self,
    ) -> jsonrpsee::http_client::HttpClient<AuthClientService<HttpBackend>> {
        // Create a middleware that adds a new JWT token to every request.
        let secret_layer = AuthClientLayer::new(self.secret);
        let middleware = tower::ServiceBuilder::default().layer(secret_layer);
        jsonrpsee::http_client::HttpClientBuilder::default()
            .set_http_middleware(middleware)
            .build(self.http_url())
            .expect("Failed to create http client")
    }
}
