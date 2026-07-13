//! Request/response client for the custodian socket.
//!
//! One in-flight request per connection — send a frame, read a frame — which
//! is why methods take `&mut self`. Callers needing concurrency open more
//! connections; the expected callers (reth at startup, attestation-service
//! per bootstrap) never need to.

use crate::error::IpcError;
use crate::framing::{read_frame, write_frame};
use crate::messages::{
    Request, Response, RngKeypairBytes, SnapshotKeyBytes, TxIoKeypairBytes, WrappedRootKeyBytes,
};
use std::path::Path;
use tokio::net::UnixStream;

pub struct CustodianClient {
    stream: UnixStream,
}

impl CustodianClient {
    pub async fn connect(path: impl AsRef<Path>) -> Result<Self, IpcError> {
        Ok(Self {
            stream: UnixStream::connect(path).await?,
        })
    }

    /// One request/response exchange. The server's failure variants become
    /// typed errors: [`Response::Denied`] → [`IpcError::Denied`],
    /// [`Response::Error`] → [`IpcError::Custodian`].
    pub async fn call(&mut self, request: &Request) -> Result<Response, IpcError> {
        write_frame(&mut self.stream, request).await?;
        match read_frame(&mut self.stream).await? {
            Some(Response::Denied { message }) => Err(IpcError::Denied(message)),
            Some(Response::Error { message }) => Err(IpcError::Custodian(message)),
            Some(response) => Ok(response),
            None => Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "custodian closed the connection",
            )
            .into()),
        }
    }

    pub async fn ping(&mut self) -> Result<(), IpcError> {
        match self.call(&Request::Ping).await? {
            Response::Pong => Ok(()),
            _ => Err(IpcError::UnexpectedResponse { method: "ping" }),
        }
    }

    pub async fn get_tx_io_keypair(&mut self, epoch: u64) -> Result<TxIoKeypairBytes, IpcError> {
        match self.call(&Request::GetTxIoKeypair { epoch }).await? {
            Response::TxIoKeypair(keys) => Ok(keys),
            _ => Err(IpcError::UnexpectedResponse {
                method: "get_tx_io_keypair",
            }),
        }
    }

    pub async fn get_rng_keypair(&mut self, epoch: u64) -> Result<RngKeypairBytes, IpcError> {
        match self.call(&Request::GetRngKeypair { epoch }).await? {
            Response::RngKeypair(keys) => Ok(keys),
            _ => Err(IpcError::UnexpectedResponse {
                method: "get_rng_keypair",
            }),
        }
    }

    pub async fn get_snapshot_key(&mut self, epoch: u64) -> Result<SnapshotKeyBytes, IpcError> {
        match self.call(&Request::GetSnapshotKey { epoch }).await? {
            Response::SnapshotKey(key) => Ok(key),
            _ => Err(IpcError::UnexpectedResponse {
                method: "get_snapshot_key",
            }),
        }
    }

    pub async fn wrap_root_key(
        &mut self,
        root_key_request_binding: [u8; 32],
        peer_eph_pk: [u8; 33],
    ) -> Result<WrappedRootKeyBytes, IpcError> {
        match self
            .call(&Request::WrapRootKey {
                root_key_request_binding,
                peer_eph_pk,
            })
            .await?
        {
            Response::WrappedRootKey(wrapped) => Ok(wrapped),
            _ => Err(IpcError::UnexpectedResponse {
                method: "wrap_root_key",
            }),
        }
    }
}
