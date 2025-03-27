use anyhow::Result;
use jsonrpsee::core::async_trait;
use jsonrpsee::core::RpcResult;
use jsonrpsee::server::ServerBuilder;
use jsonrpsee::{
    http_client::transport::HttpBackend,
    server::{AlreadyStoppedError, RpcModule},
};
use seismic_enclave::client::ENCLAVE_DEFAULT_PUBLIC_PORT;
use std::net::SocketAddr;
use tower::layer::util::Identity;

use crate::key_manager::builder::KeyManagerBuilder;
use crate::key_manager::key_manager::KeyManager;
use crate::key_manager::NetworkKeyProvider;
use seismic_enclave::client::public::EnclavePublicAPIServer;
use seismic_enclave::ENCLAVE_DEFAULT_ENDPOINT_ADDR;

// Implements the EnclavePublicAPIServer trait, i.e. the expected endpoints
pub struct EnclavePublicServer {
    key_manager: KeyManager,
}
impl EnclavePublicServer {
    pub fn new() -> Self {
        Self {
            // TODO: use real key manager
            key_manager: KeyManagerBuilder::build_mock().unwrap(),
        }
    }
}
#[async_trait]
impl EnclavePublicAPIServer for EnclavePublicServer {
    /// Handler for: `healthCheck`
    async fn health_check(&self) -> RpcResult<String> {
        Ok("OK".into())
    }

    /// Handler for: `getPublicKey`
    async fn get_public_key(&self) -> RpcResult<secp256k1::PublicKey> {
        Ok(self.key_manager.get_tx_io_pk())
    }
}

// The RPC module for the enclave public server
// Takes in the EnclavePublicAPIServer trait converts it
// to a generic RPC module so that it can be grouped with other RPC modules
// With a EnclavePublicServerConfig, defines a convenience function for starting the server
pub struct EnclavePublicRPCModule {
    inner: RpcModule<()>,
}
impl EnclavePublicRPCModule {
    pub fn new<EnclavePublicServer>(public_server: EnclavePublicServer) -> Self
    where
        EnclavePublicServer: EnclavePublicAPIServer,
    {
        let mut module = RpcModule::new(());
        module
            .merge(public_server.into_rpc())
            .expect("No conflicting methods");
        Self { inner: module }
    }

    /// Get a reference to the inner `RpcModule`.
    pub fn module_mut(&mut self) -> &mut RpcModule<()> {
        &mut self.inner
    }

    /// Convenience function for starting a server
    pub async fn start_server(
        self,
        config: EnclavePublicServerConfig,
    ) -> Result<EnclavePublicHandle, anyhow::Error> {
        config.start(self).await
    }
}

/// EnclavePublicServerConfig is a configuration for a enclave public RPC server
/// It defines the parts of the server that are unrelated to the API,
/// i.e. ports, auth, middlewares, etc.
/// With a EnclavePublicRPCModule, defines a convenience function for starting the server
pub struct EnclavePublicServerConfig {
    /// Where the server should listen.
    pub(crate) socket_addr: SocketAddr,
    /// Configs for JSON-RPC Http.
    pub(crate) server_config: ServerBuilder<Identity, Identity>,
}
impl EnclavePublicServerConfig {
    pub fn default() -> Self {
        Self {
            socket_addr: SocketAddr::new(
                ENCLAVE_DEFAULT_ENDPOINT_ADDR,
                ENCLAVE_DEFAULT_PUBLIC_PORT,
            ),
            server_config: ServerBuilder::new(),
        }
    }

    /// Returns the address the server will listen on.
    pub const fn address(&self) -> SocketAddr {
        self.socket_addr
    }

    /// Convenience function to start a server in one step.
    pub async fn start(
        self,
        module: EnclavePublicRPCModule,
    ) -> Result<EnclavePublicHandle, anyhow::Error> {
        let Self {
            socket_addr,
            server_config,
        } = self;

        let server = server_config.build(socket_addr).await?;

        let local_addr = server.local_addr()?;

        let handle = server.start(module.inner.clone());

        Ok(EnclavePublicHandle { handle, local_addr })
    }
}

// EnclavePublicHandle is a handle for a spawned enclave public RPC server
#[derive(Debug, Clone)]
pub struct EnclavePublicHandle {
    local_addr: SocketAddr,
    handle: jsonrpsee::server::ServerHandle,
}

impl EnclavePublicHandle {
    /// Returns the [`SocketAddr`] of the http server if started.
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Tell the server to stop without waiting for the server to stop.
    pub fn stop(&self) -> Result<(), AlreadyStoppedError> {
        self.handle.stop()
    }

    pub fn is_stopped(&self) -> bool {
        self.handle.is_stopped()
    }

    /// Returns the url to the http server
    pub fn http_url(&self) -> String {
        format!("http://{}", self.local_addr)
    }

    /// Returns a default http client connected to the server,
    pub fn http_client(&self) -> jsonrpsee::http_client::HttpClient<HttpBackend> {
        jsonrpsee::http_client::HttpClientBuilder::default()
            .build(self.http_url())
            .expect("Failed to create http client")
    }
}
