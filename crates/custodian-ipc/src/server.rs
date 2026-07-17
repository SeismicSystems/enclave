//! Synchronous Unix-socket server for the custodian protocol.
//!
//! Deliberately not async: the socket serves two or three long-lived local
//! clients with single-digit requests per process lifetime, so a thread per
//! connection is the entire concurrency requirement and the key-holding
//! process links no async runtime. Hosts inject *dispatch* as a closure —
//! this crate never touches key material or depends on the custodian; it
//! owns only the transport: bind semantics, peer credentials, ACL
//! enforcement (structurally before dispatch), and the frame loop.
//!
//! Call [`serve`] from a dedicated thread; it blocks forever.

use crate::framing::{read_frame_blocking, write_frame_blocking};
use crate::messages::{Request, Response};
use std::collections::HashSet;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tracing::{info, warn};

/// Upper bound on concurrent connections (and thus per-connection threads).
/// Legitimate callers number in the single digits; the cap only exists so a
/// misbehaving authorized client can't grow threads without bound.
const MAX_CONNECTIONS: usize = 64;

/// Which peer UIDs may call which methods, one allowlist per purpose so each
/// caller is granted exactly the keys it needs. `Ping` is open to anyone who
/// can connect (it carries no key material); everything else is
/// deny-by-default — `MethodAcl::default()` denies all.
#[derive(Default)]
pub struct MethodAcl {
    /// UIDs allowed the tx-io keypair (reth: TxSeismic calldata).
    pub tx_io: HashSet<u32>,
    /// UIDs allowed only the public half of the tx-io key (attestation
    /// service: tx-io evidence generation).
    pub tx_io_public: HashSet<u32>,
    /// UIDs allowed the RNG-precompile keypair (reth: EVM randomness).
    pub rng: HashSet<u32>,
    /// UIDs allowed the snapshot key (the snapshot service; NOT reth).
    pub snapshot: HashSet<u32>,
    /// UIDs allowed to ask a custodian without a root key to retain a fresh
    /// requester-side bootstrap secret.
    pub create_root_key_bootstrap_attempt: HashSet<u32>,
    /// UIDs allowed to request root-key wraps. A caller here is trusted to
    /// have verified peer attestation first — confine to attestation-service.
    pub wrap_root_key: HashSet<u32>,
    /// UIDs trusted to have verified a responder and install its wrapped root
    /// key. Confine to attestation-service.
    pub install_root_key_from_verified_bootstrap_response: HashSet<u32>,
}

impl MethodAcl {
    /// Default until dedicated per-service users exist: only this process's
    /// own effective UID, on every method. Exercises the socket end-to-end
    /// while every legitimate caller still lives in the host process.
    pub fn own_uid_only() -> Self {
        // SAFETY: geteuid has no failure modes and touches no memory.
        let uid = unsafe { libc::geteuid() };
        let own = HashSet::from([uid]);
        Self {
            tx_io: own.clone(),
            tx_io_public: own.clone(),
            rng: own.clone(),
            snapshot: own.clone(),
            create_root_key_bootstrap_attempt: own.clone(),
            wrap_root_key: own.clone(),
            install_root_key_from_verified_bootstrap_response: own,
        }
    }

    pub fn allows(&self, uid: u32, request: &Request) -> bool {
        match request {
            Request::Ping => true,
            Request::GetTxIoKeypair { .. } => self.tx_io.contains(&uid),
            Request::GetTxIoPublicKey { .. } => self.tx_io_public.contains(&uid),
            Request::GetRngIkm { .. } => self.rng.contains(&uid),
            Request::GetSnapshotKey { .. } => self.snapshot.contains(&uid),
            Request::CreateRootKeyBootstrapAttempt => {
                self.create_root_key_bootstrap_attempt.contains(&uid)
            }
            Request::WrapRootKey { .. } => self.wrap_root_key.contains(&uid),
            Request::InstallRootKeyFromVerifiedBootstrapResponse { .. } => self
                .install_root_key_from_verified_bootstrap_response
                .contains(&uid),
        }
    }
}

/// Bind the custodian socket. Separate from [`serve`] so hosts can fail hard
/// at startup if the socket can't exist (and tests can bind a tmpdir path).
pub fn bind(path: &Path) -> std::io::Result<UnixListener> {
    // A previous run's socket inode makes bind() fail even though nothing is
    // listening; remove it. /run is tmpfs so this only matters for restarts.
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = UnixListener::bind(path)?;
    // 0660: owner + group only. The group decides who may even connect;
    // MethodAcl decides what a connected UID may call.
    fs::set_permissions(path, fs::Permissions::from_mode(0o660))?;
    info!("custodian IPC listening on {}", path.display());
    Ok(listener)
}

/// Accept loop: one thread per connection, `handler` invoked only for
/// requests the ACL allows for the peer's kernel-reported UID. Blocks
/// forever; per-connection errors are logged and drop only that connection.
pub fn serve<H>(listener: UnixListener, acl: MethodAcl, handler: H)
where
    H: Fn(Request) -> Response + Send + Sync + 'static,
{
    let acl = Arc::new(acl);
    let handler = Arc::new(handler);
    let active = Arc::new(AtomicUsize::new(0));
    loop {
        let (stream, _addr) = match listener.accept() {
            Ok(conn) => conn,
            Err(e) => {
                warn!("custodian IPC: accept failed: {e}");
                continue;
            }
        };
        let uid = match peer_uid(&stream) {
            Ok(uid) => uid,
            Err(e) => {
                // No credentials means no ACL decision; never serve blind.
                warn!("custodian IPC: dropping connection without peer creds: {e}");
                continue;
            }
        };
        if active.load(Ordering::Acquire) >= MAX_CONNECTIONS {
            warn!(uid, "custodian IPC: connection limit reached, dropping");
            continue;
        }
        active.fetch_add(1, Ordering::AcqRel);
        let (acl, handler, active) = (acl.clone(), handler.clone(), active.clone());
        std::thread::spawn(move || {
            // Decrement via a drop guard so a panicking handler can't leak
            // the slot — 64 leaked slots would stop the socket serving keys.
            struct SlotGuard(Arc<AtomicUsize>);
            impl Drop for SlotGuard {
                fn drop(&mut self) {
                    self.0.fetch_sub(1, Ordering::AcqRel);
                }
            }
            let _slot = SlotGuard(active);
            handle_connection(stream, uid, &acl, &*handler);
        });
    }
}

/// Serve one connection whose peer the kernel identified as `uid`. Generic
/// over the stream so the request/ACL/dispatch path is testable over
/// in-memory buffers; only [`serve`] touches real sockets and peer creds.
fn handle_connection<S, H>(mut stream: S, uid: u32, acl: &MethodAcl, handler: &H)
where
    S: Read + Write,
    H: Fn(Request) -> Response + ?Sized,
{
    loop {
        let request: Request = match read_frame_blocking(&mut stream) {
            Ok(Some(request)) => request,
            Ok(None) => return, // peer closed
            Err(e) => {
                warn!(uid, "custodian IPC: dropping connection: {e}");
                return;
            }
        };
        let response = if acl.allows(uid, &request) {
            handler(request)
        } else {
            warn!(
                uid,
                method = request.method(),
                "custodian IPC: denied by ACL"
            );
            Response::Denied {
                message: format!("uid {uid} is not authorized for {}", request.method()),
            }
        };
        if let Err(e) = write_frame_blocking(&mut stream, &response) {
            warn!(uid, "custodian IPC: write failed: {e}");
            return;
        }
    }
}

/// Kernel-reported UID of the connected peer. std's `peer_cred()` is
/// unstable, so ask libc directly.
#[cfg(target_os = "linux")]
fn peer_uid(stream: &UnixStream) -> std::io::Result<u32> {
    use std::os::fd::AsRawFd as _;
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: fd is a live socket owned by `stream`; the kernel writes at
    // most `len` bytes into `cred`, which is sized for exactly that.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut cred).cast(),
            &raw mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(cred.uid)
}

/// macOS analogue of `SO_PEERCRED`, for dev machines; production is Linux.
#[cfg(target_os = "macos")]
fn peer_uid(stream: &UnixStream) -> std::io::Result<u32> {
    use std::os::fd::AsRawFd as _;
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: fd is a live socket owned by `stream`; getpeereid writes one
    // uid_t and one gid_t through the provided pointers.
    let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &raw mut uid, &raw mut gid) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(uid)
}

// Fail loudly on an unsupported target instead of compiling a server that
// cannot authenticate its peers.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("custodian IPC server requires SO_PEERCRED or getpeereid");

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framing::encode_frame;
    use std::io::Cursor;

    const UID: u32 = 1000;

    /// In-memory stand-in for a connection: reads scripted request frames,
    /// captures response frames.
    struct ScriptedStream {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
    }

    impl Read for ScriptedStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(buf)
        }
    }

    impl Write for ScriptedStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.output.write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Run one connection to completion and return the responses.
    fn run_connection<H>(
        requests: &[Request],
        uid: u32,
        acl: &MethodAcl,
        handler: H,
    ) -> Vec<Response>
    where
        H: Fn(Request) -> Response,
    {
        let mut wire = Vec::new();
        for request in requests {
            wire.extend(encode_frame(request).expect("encode"));
        }
        let mut stream = ScriptedStream {
            input: Cursor::new(wire),
            output: Vec::new(),
        };
        handle_connection(&mut stream, uid, acl, &handler);
        let mut reader = stream.output.as_slice();
        let mut responses = Vec::new();
        while let Some(response) = read_frame_blocking(&mut reader).expect("read response") {
            responses.push(response);
        }
        responses
    }

    fn allow_all_for(uid: u32) -> MethodAcl {
        let own = HashSet::from([uid]);
        MethodAcl {
            tx_io: own.clone(),
            tx_io_public: own.clone(),
            rng: own.clone(),
            snapshot: own.clone(),
            create_root_key_bootstrap_attempt: own.clone(),
            wrap_root_key: own.clone(),
            install_root_key_from_verified_bootstrap_response: own,
        }
    }

    #[test]
    fn handler_sees_allowed_requests() {
        let responses = run_connection(
            &[Request::Ping, Request::GetTxIoKeypair { epoch: 4 }],
            UID,
            &allow_all_for(UID),
            |request| match request {
                Request::Ping => Response::Pong,
                Request::GetTxIoKeypair { epoch } => Response::Error {
                    message: format!("handler saw epoch {epoch}"),
                },
                _ => unreachable!(),
            },
        );
        assert!(matches!(responses[0], Response::Pong));
        let Response::Error { message } = &responses[1] else {
            panic!("expected handler response");
        };
        assert_eq!(message, "handler saw epoch 4");
    }

    #[test]
    fn denied_request_never_reaches_handler_but_ping_does() {
        let responses = run_connection(
            &[
                Request::GetTxIoKeypair { epoch: 0 },
                Request::Ping, // a denial answers the request; it doesn't poison the connection
            ],
            UID,
            &MethodAcl::default(), // deny-all
            |request| match request {
                Request::Ping => Response::Pong,
                _ => panic!("handler must not see denied requests"),
            },
        );
        let Response::Denied { message } = &responses[0] else {
            panic!("expected denial");
        };
        assert!(message.contains("not authorized"), "{message}");
        assert!(matches!(responses[1], Response::Pong));
    }

    // The production grant matrix: reth receives only the key material needed
    // for execution, while the attestation service receives public tx-io data
    // and root-key bootstrap authority, never secret purpose keys.
    #[test]
    fn caller_grants_are_independent() {
        let reth_like = MethodAcl {
            tx_io: HashSet::from([UID]),
            rng: HashSet::from([UID]),
            ..MethodAcl::default()
        };
        assert!(reth_like.allows(UID, &Request::GetTxIoKeypair { epoch: 0 }));
        assert!(reth_like.allows(UID, &Request::GetRngIkm { epoch: 0 }));
        assert!(!reth_like.allows(UID, &Request::GetTxIoPublicKey { epoch: 0 }));
        assert!(!reth_like.allows(UID, &Request::GetSnapshotKey { epoch: 0 }));
        assert!(!reth_like.allows(UID, &Request::CreateRootKeyBootstrapAttempt));
        assert!(!reth_like.allows(UID, &wrap_request()));
        assert!(!reth_like.allows(UID, &install_request()));

        let attestation_like = MethodAcl {
            tx_io_public: HashSet::from([UID]),
            create_root_key_bootstrap_attempt: HashSet::from([UID]),
            wrap_root_key: HashSet::from([UID]),
            install_root_key_from_verified_bootstrap_response: HashSet::from([UID]),
            ..MethodAcl::default()
        };
        assert!(attestation_like.allows(UID, &Request::GetTxIoPublicKey { epoch: 0 }));
        assert!(attestation_like.allows(UID, &Request::CreateRootKeyBootstrapAttempt));
        assert!(attestation_like.allows(UID, &wrap_request()));
        assert!(attestation_like.allows(UID, &install_request()));
        assert!(!attestation_like.allows(UID, &Request::GetTxIoKeypair { epoch: 0 }));
        assert!(!attestation_like.allows(UID, &Request::GetRngIkm { epoch: 0 }));
        assert!(!attestation_like.allows(UID, &Request::GetSnapshotKey { epoch: 0 }));

        assert!(!reth_like.allows(UID + 1, &Request::GetTxIoKeypair { epoch: 0 }));
        assert!(!attestation_like.allows(UID + 1, &wrap_request()));
    }

    fn wrap_request() -> Request {
        Request::WrapRootKey {
            root_key_request_binding: [0; 32],
            peer_eph_pk: [0; 33],
        }
    }

    fn install_request() -> Request {
        Request::InstallRootKeyFromVerifiedBootstrapResponse {
            attempt_id: [0; 32],
            root_key_request_binding: [0; 32],
            responder_eph_pk: [0; 33],
            wrapped_root_key: Vec::new(),
        }
    }

    #[test]
    fn oversize_frame_drops_connection_without_reply() {
        let mut stream = ScriptedStream {
            input: Cursor::new(u32::MAX.to_be_bytes().to_vec()),
            output: Vec::new(),
        };
        handle_connection(&mut stream, UID, &allow_all_for(UID), &|_| Response::Pong);
        assert!(
            stream.output.is_empty(),
            "server must close on an oversize frame, not answer"
        );
    }
}
