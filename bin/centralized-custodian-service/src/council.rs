//! The council delivery port: a synchronous TCP server for
//! [`CouncilRequest`]s, framed exactly like the custodian Unix socket
//! (4-byte big-endian length + CBOR, 64 KiB cap).
//!
//! The transport is deliberately unauthenticated: authentication is the
//! council signature carried inside each delivery envelope, and the
//! unauthenticated methods (`Ping`, `GetStatus`) reveal only public data.
//! Reachability confinement (firewalling the port to council egress) is the
//! image's affair. The accept loop mirrors `custodian_ipc::server::serve`:
//! thread per connection, a capped connection count with a drop-guard, and
//! per-connection I/O timeouts so an idle or stalled peer can't hold a slot
//! forever.

use crate::state::CentralizedCustodianState;
use seismic_council_delivery::{CouncilRequest, CouncilResponse};
use seismic_custodian_ipc::{read_frame_blocking, write_frame_blocking};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tracing::{info, warn};

/// Legitimate traffic is one council client making single-digit deliveries;
/// the cap only bounds thread growth against misuse of the open port.
const MAX_COUNCIL_CONNECTIONS: usize = 16;
/// A council connection that can't move a frame in this long is dropped.
const COUNCIL_IO_TIMEOUT: Duration = Duration::from_secs(30);

/// Accept loop for the council port. Blocks forever; call from a dedicated
/// thread. Per-connection errors drop only that connection.
pub fn serve_council(listener: TcpListener, state: Arc<CentralizedCustodianState>) {
    if let Ok(addr) = listener.local_addr() {
        info!("council delivery port listening on {addr}");
    }
    let active = Arc::new(AtomicUsize::new(0));
    loop {
        let (stream, peer) = match listener.accept() {
            Ok(conn) => conn,
            Err(e) => {
                warn!("council port: accept failed: {e}");
                continue;
            }
        };
        if active.load(Ordering::Acquire) >= MAX_COUNCIL_CONNECTIONS {
            warn!(%peer, "council port: connection limit reached, dropping");
            continue;
        }
        if stream
            .set_read_timeout(Some(COUNCIL_IO_TIMEOUT))
            .and_then(|()| stream.set_write_timeout(Some(COUNCIL_IO_TIMEOUT)))
            .is_err()
        {
            warn!(%peer, "council port: could not set socket timeouts, dropping");
            continue;
        }
        active.fetch_add(1, Ordering::AcqRel);
        let (state, active) = (state.clone(), active.clone());
        std::thread::spawn(move || {
            // Decrement via a drop guard so a panicking handler can't leak
            // the slot (same discipline as the unix-socket server).
            struct SlotGuard(Arc<AtomicUsize>);
            impl Drop for SlotGuard {
                fn drop(&mut self) {
                    self.0.fetch_sub(1, Ordering::AcqRel);
                }
            }
            let _slot = SlotGuard(active);
            let mut stream = stream;
            handle_council_connection(&mut stream, &state);
        });
    }
}

/// Serve one council connection. Generic over the stream so the
/// request/response path is testable over in-memory buffers; only
/// [`serve_council`] touches real sockets. Frame errors (oversize, garbage,
/// timeout) drop the connection without a reply, matching the unix-socket
/// discipline.
fn handle_council_connection<S: Read + Write>(stream: &mut S, state: &CentralizedCustodianState) {
    loop {
        let request: CouncilRequest = match read_frame_blocking(stream) {
            Ok(Some(request)) => request,
            Ok(None) => return, // peer closed
            Err(e) => {
                warn!("council port: dropping connection: {e}");
                return;
            }
        };
        let response = match &request {
            CouncilRequest::Ping => CouncilResponse::Pong,
            CouncilRequest::GetStatus => CouncilResponse::Status(state.status()),
            CouncilRequest::DeliverEpochKey(envelope) => state.deliver(envelope),
        };
        info!(
            method = request.method(),
            outcome = response.kind(),
            "council request"
        );
        if let Err(e) = write_frame_blocking(stream, &response) {
            warn!("council port: write failed: {e}");
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{PURPOSE_KEY, build_state, seal};
    use seismic_council_delivery::DeliveryPurpose;
    use std::io::Cursor;

    /// In-memory stand-in for a TCP connection: reads scripted request
    /// frames, captures response frames.
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

    fn run_connection(
        requests: &[CouncilRequest],
        state: &CentralizedCustodianState,
    ) -> Vec<CouncilResponse> {
        let mut wire = Vec::new();
        for request in requests {
            write_frame_blocking(&mut wire, request).expect("encode request");
        }
        let mut stream = ScriptedStream {
            input: Cursor::new(wire),
            output: Vec::new(),
        };
        handle_council_connection(&mut stream, state);
        let mut reader = stream.output.as_slice();
        let mut responses = Vec::new();
        while let Some(response) =
            read_frame_blocking::<_, CouncilResponse>(&mut reader).expect("read response")
        {
            responses.push(response);
        }
        responses
    }

    #[test]
    fn ping_status_and_delivery_over_one_connection() {
        let dir = tempfile::tempdir().unwrap();
        let state = build_state(dir.path());
        let responses = run_connection(
            &[
                CouncilRequest::Ping,
                CouncilRequest::GetStatus,
                CouncilRequest::DeliverEpochKey(seal(DeliveryPurpose::TxIo, 1, PURPOSE_KEY)),
                CouncilRequest::GetStatus,
            ],
            &state,
        );
        assert!(matches!(responses[0], CouncilResponse::Pong));
        let CouncilResponse::Status(before) = &responses[1] else {
            panic!("expected status");
        };
        assert_eq!(before.tx_io_epoch, 0);
        assert!(matches!(
            responses[2],
            CouncilResponse::Delivered { epoch: 1, .. }
        ));
        let CouncilResponse::Status(after) = &responses[3] else {
            panic!("expected status");
        };
        assert_eq!(after.tx_io_epoch, 1);
    }

    #[test]
    fn oversize_frame_drops_connection_without_reply() {
        let dir = tempfile::tempdir().unwrap();
        let state = build_state(dir.path());
        let mut stream = ScriptedStream {
            input: Cursor::new(u32::MAX.to_be_bytes().to_vec()),
            output: Vec::new(),
        };
        handle_council_connection(&mut stream, &state);
        assert!(
            stream.output.is_empty(),
            "server must close on an oversize frame, not answer"
        );
    }

    #[test]
    fn garbage_frame_drops_connection_without_reply() {
        let dir = tempfile::tempdir().unwrap();
        let state = build_state(dir.path());
        let mut wire = 9u32.to_be_bytes().to_vec();
        wire.extend_from_slice(b"not cbor!");
        let mut stream = ScriptedStream {
            input: Cursor::new(wire),
            output: Vec::new(),
        };
        handle_council_connection(&mut stream, &state);
        assert!(stream.output.is_empty());
    }
}
