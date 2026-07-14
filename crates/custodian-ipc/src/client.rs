//! Request/response client for the custodian socket.
//!
//! One in-flight request per connection — send a frame, read a frame — which
//! is why methods take `&mut self`. Callers needing concurrency open more
//! connections; the expected callers (reth at startup, attestation-service
//! per bootstrap) never need to.

use crate::error::IpcError;
use crate::framing::{read_frame, write_frame};
use crate::messages::{
    Request, Response, RngKeypairBytes, RootKeyBootstrapAttemptBytes, SnapshotKeyBytes,
    TxIoKeypairBytes, TxIoPublicKeyBytes, WrappedRootKeyBytes,
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
            Some(Response::RootKeyAbsent) => Err(IpcError::RootKeyAbsent),
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
            response => Err(unexpected_response("ping", &response)),
        }
    }

    pub async fn get_tx_io_keypair(&mut self, epoch: u64) -> Result<TxIoKeypairBytes, IpcError> {
        match self.call(&Request::GetTxIoKeypair { epoch }).await? {
            Response::TxIoKeypair(keys) => Ok(keys),
            response => Err(unexpected_response("get_tx_io_keypair", &response)),
        }
    }

    pub async fn get_tx_io_public_key(
        &mut self,
        epoch: u64,
    ) -> Result<TxIoPublicKeyBytes, IpcError> {
        match self.call(&Request::GetTxIoPublicKey { epoch }).await? {
            Response::TxIoPublicKey(key) => Ok(key),
            response => Err(unexpected_response("get_tx_io_public_key", &response)),
        }
    }

    pub async fn get_rng_keypair(&mut self, epoch: u64) -> Result<RngKeypairBytes, IpcError> {
        match self.call(&Request::GetRngKeypair { epoch }).await? {
            Response::RngKeypair(keys) => Ok(keys),
            response => Err(unexpected_response("get_rng_keypair", &response)),
        }
    }

    pub async fn get_snapshot_key(&mut self, epoch: u64) -> Result<SnapshotKeyBytes, IpcError> {
        match self.call(&Request::GetSnapshotKey { epoch }).await? {
            Response::SnapshotKey(key) => Ok(key),
            response => Err(unexpected_response("get_snapshot_key", &response)),
        }
    }

    /// Start requester-side bootstrap. `RootKeyAlreadyPresent` is an expected
    /// outcome after an attestation-service restart, not an IPC failure.
    pub async fn create_root_key_bootstrap_attempt(
        &mut self,
    ) -> Result<CreateRootKeyBootstrapAttemptResult, IpcError> {
        match self.call(&Request::CreateRootKeyBootstrapAttempt).await? {
            Response::RootKeyBootstrapAttemptCreated(attempt) => {
                Ok(CreateRootKeyBootstrapAttemptResult::Created(attempt))
            }
            Response::RootKeyAlreadyPresent => {
                Ok(CreateRootKeyBootstrapAttemptResult::RootKeyAlreadyPresent)
            }
            response => Err(unexpected_response(
                "create_root_key_bootstrap_attempt",
                &response,
            )),
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
            response => Err(unexpected_response("wrap_root_key", &response)),
        }
    }

    pub async fn install_root_key_from_verified_bootstrap_response(
        &mut self,
        attempt_id: [u8; 32],
        root_key_request_binding: [u8; 32],
        responder_eph_pk: [u8; 33],
        wrapped_root_key: Vec<u8>,
    ) -> Result<InstallRootKeyFromVerifiedBootstrapResponseResult, IpcError> {
        match self
            .call(&Request::InstallRootKeyFromVerifiedBootstrapResponse {
                attempt_id,
                root_key_request_binding,
                responder_eph_pk,
                wrapped_root_key,
            })
            .await?
        {
            Response::RootKeyInstalled => {
                Ok(InstallRootKeyFromVerifiedBootstrapResponseResult::Installed)
            }
            Response::RootKeyAlreadyPresent => {
                Ok(InstallRootKeyFromVerifiedBootstrapResponseResult::RootKeyAlreadyPresent)
            }
            response => Err(unexpected_response(
                "install_root_key_from_verified_bootstrap_response",
                &response,
            )),
        }
    }
}

fn unexpected_response(method: &'static str, response: &Response) -> IpcError {
    IpcError::UnexpectedResponse {
        method,
        received: response.kind(),
    }
}

/// Outcome of [`CustodianClient::create_root_key_bootstrap_attempt`].
#[derive(Debug, Clone)]
pub enum CreateRootKeyBootstrapAttemptResult {
    /// A fresh requester ephemeral secret is retained under this attempt.
    Created(RootKeyBootstrapAttemptBytes),
    /// Bootstrap is unnecessary because this custodian already holds the key.
    RootKeyAlreadyPresent,
}

/// Outcome of
/// [`CustodianClient::install_root_key_from_verified_bootstrap_response`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallRootKeyFromVerifiedBootstrapResponseResult {
    /// The wrapped response was opened and its root key installed.
    Installed,
    /// The custodian already held a root key, so it installed nothing.
    RootKeyAlreadyPresent,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scripted_client(response: Response) -> (CustodianClient, tokio::task::JoinHandle<Request>) {
        let (client_stream, mut server_stream) = UnixStream::pair().expect("UnixStream pair");
        let server = tokio::spawn(async move {
            let request = read_frame(&mut server_stream)
                .await
                .expect("read request")
                .expect("request frame");
            write_frame(&mut server_stream, &response)
                .await
                .expect("write response");
            request
        });
        (
            CustodianClient {
                stream: client_stream,
            },
            server,
        )
    }

    #[tokio::test]
    async fn new_methods_map_successful_responses() {
        let (mut client, server) =
            scripted_client(Response::TxIoPublicKey(TxIoPublicKeyBytes { pk: [2; 33] }));
        let public_key = client.get_tx_io_public_key(7).await.expect("public key");
        assert_eq!(public_key.pk, [2; 33]);
        assert!(matches!(
            server.await.expect("server task"),
            Request::GetTxIoPublicKey { epoch: 7 }
        ));

        let attempt = RootKeyBootstrapAttemptBytes {
            attempt_id: [3; 32],
            requester_eph_pk: [4; 33],
        };
        let (mut client, server) =
            scripted_client(Response::RootKeyBootstrapAttemptCreated(attempt.clone()));
        let result = client
            .create_root_key_bootstrap_attempt()
            .await
            .expect("create attempt");
        let CreateRootKeyBootstrapAttemptResult::Created(created) = result else {
            panic!("expected a created attempt");
        };
        assert_eq!(created.attempt_id, attempt.attempt_id);
        assert_eq!(created.requester_eph_pk, attempt.requester_eph_pk);
        assert!(matches!(
            server.await.expect("server task"),
            Request::CreateRootKeyBootstrapAttempt
        ));

        let (mut client, server) = scripted_client(Response::RootKeyInstalled);
        let result = client
            .install_root_key_from_verified_bootstrap_response(
                [5; 32],
                [6; 32],
                [7; 33],
                vec![8; 60],
            )
            .await
            .expect("install root key");
        assert_eq!(
            result,
            InstallRootKeyFromVerifiedBootstrapResponseResult::Installed
        );
        let Request::InstallRootKeyFromVerifiedBootstrapResponse {
            attempt_id,
            root_key_request_binding,
            responder_eph_pk,
            wrapped_root_key,
        } = server.await.expect("server task")
        else {
            panic!("expected install request");
        };
        assert_eq!(attempt_id, [5; 32]);
        assert_eq!(root_key_request_binding, [6; 32]);
        assert_eq!(responder_eph_pk, [7; 33]);
        assert_eq!(wrapped_root_key, vec![8; 60]);
    }

    #[tokio::test]
    async fn state_and_handler_failures_remain_typed() {
        let (mut client, server) = scripted_client(Response::RootKeyAbsent);
        let error = client.get_rng_keypair(0).await.expect_err("must fail");
        assert!(matches!(error, IpcError::RootKeyAbsent));
        server.await.expect("server task");

        let (mut client, server) = scripted_client(Response::Error {
            message: "stable custodian error".into(),
        });
        let error = client.get_snapshot_key(0).await.expect_err("must fail");
        assert!(matches!(
            error,
            IpcError::Custodian(message) if message == "stable custodian error"
        ));
        server.await.expect("server task");
    }

    #[tokio::test]
    async fn unexpected_response_reports_only_its_kind() {
        let (mut client, server) = scripted_client(Response::TxIoKeypair(TxIoKeypairBytes {
            sk: [0xA5; 32],
            pk: [2; 33],
        }));
        let error = client
            .get_tx_io_public_key(0)
            .await
            .expect_err("wrong response variant must fail");
        let rendered = error.to_string();
        assert!(matches!(
            error,
            IpcError::UnexpectedResponse {
                method: "get_tx_io_public_key",
                received: "tx_io_keypair"
            }
        ));
        assert!(
            !rendered.contains("165"),
            "secret payload leaked: {rendered}"
        );
        server.await.expect("server task");
    }
}
