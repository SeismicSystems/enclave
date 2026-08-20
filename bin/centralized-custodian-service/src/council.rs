//! The council delivery port: a synchronous TCP server for
//! [`CouncilRequest`]s, framed exactly like the custodian Unix socket
//! (4-byte big-endian length + CBOR, 64 KiB cap).
//!
//! The transport is deliberately unauthenticated: authentication is the
//! council signature carried inside each delivery envelope — and, for
//! observer fetches, the ed25519 child-key signature over a per-connection
//! single-use challenge nonce. The unauthenticated methods (`Ping`,
//! `GetStatus`) reveal only public data. Observer fetches return secrets
//! (the root key, plaintext envelopes), so the transport-confidentiality
//! assumption the port already documents for deliveries — a TLS terminator
//! or tunnel in front of it — covers those responses too. Reachability
//! confinement (firewalling the port to council and observer egress) is the
//! image's affair. The accept loop mirrors `custodian_ipc::server::serve`:
//! thread per connection, a capped connection count with a drop-guard, and
//! per-connection I/O timeouts so an idle or stalled peer can't hold a slot
//! forever.

use crate::observer_serving::ObserverServing;
use crate::state::CentralizedCustodianState;
use seismic_council_delivery::{
    CouncilRequest, CouncilResponse, MAX_ENVELOPES_PER_FETCH, ObserverQuery, ObserverRejectCode,
    ObserverRootKey,
};
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
/// `observer_serving` is `Some` only when the custodian was given a
/// `--summit-key-dir`; without it observer requests get a typed rejection.
pub fn serve_council(
    listener: TcpListener,
    state: Arc<CentralizedCustodianState>,
    observer_serving: Option<Arc<ObserverServing>>,
) {
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
        let observer_serving = observer_serving.clone();
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
            handle_council_connection(
                &mut stream,
                &state,
                observer_serving.as_deref(),
                &mut random_nonce,
            );
        });
    }
}

/// OS-CSPRNG challenge nonce (production; tests inject a deterministic one).
fn random_nonce() -> [u8; 32] {
    use rand::RngCore as _;
    let mut nonce = [0u8; 32];
    rand::rng().fill_bytes(&mut nonce);
    nonce
}

/// Serve one council connection. Generic over the stream (and over nonce
/// generation) so the request/response path is testable over in-memory
/// buffers with deterministic nonces; only [`serve_council`] touches real
/// sockets. Frame errors (oversize, garbage, timeout) drop the connection
/// without a reply, matching the unix-socket discipline.
///
/// Challenge state is connection-local and single-use: each
/// `ObserverChallenge` stores a fresh nonce (replacing any unconsumed one),
/// and each `ObserverFetch` consumes it — a second fetch without a new
/// challenge fails with `MissingChallenge`, which is the replay protection.
pub fn handle_council_connection<S: Read + Write>(
    stream: &mut S,
    state: &CentralizedCustodianState,
    observer_serving: Option<&ObserverServing>,
    next_nonce: &mut dyn FnMut() -> [u8; 32],
) {
    let mut challenge: Option<[u8; 32]> = None;
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
            CouncilRequest::ObserverChallenge => match observer_serving {
                None => not_serving_observers(),
                Some(_) => {
                    let nonce = next_nonce();
                    challenge = Some(nonce);
                    CouncilResponse::Challenge { nonce }
                }
            },
            CouncilRequest::ObserverFetch { request, signature } => match observer_serving {
                None => not_serving_observers(),
                Some(serving) => {
                    match serving.verify_fetch(
                        state.network_id(),
                        challenge.take(),
                        request,
                        signature,
                    ) {
                        Err((code, message)) => {
                            warn!(
                                ?code,
                                index = request.observer_index,
                                "observer fetch refused"
                            );
                            CouncilResponse::ObserverRejected {
                                code,
                                message: message.to_string(),
                            }
                        }
                        Ok(()) => match request.query {
                            ObserverQuery::RootKey => CouncilResponse::RootKey(ObserverRootKey {
                                key: serving.root_key(),
                            }),
                            ObserverQuery::Envelopes {
                                purpose,
                                from_epoch,
                            } => {
                                let (envelopes, delivered_epoch) = state.envelopes_from(
                                    purpose,
                                    from_epoch,
                                    MAX_ENVELOPES_PER_FETCH,
                                );
                                CouncilResponse::Envelopes {
                                    envelopes,
                                    delivered_epoch,
                                }
                            }
                        },
                    }
                }
            },
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

fn not_serving_observers() -> CouncilResponse {
    CouncilResponse::ObserverRejected {
        code: ObserverRejectCode::NotServingObservers,
        message: "this custodian has no summit key dir and does not serve observers".to_string(),
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

    /// Deterministic nonce sequence for tests: 1, 2, 3, ... in every byte.
    fn counting_nonce() -> impl FnMut() -> [u8; 32] {
        let mut counter = 0u8;
        move || {
            counter += 1;
            [counter; 32]
        }
    }

    fn run_connection_with(
        requests: &[CouncilRequest],
        state: &CentralizedCustodianState,
        observer_serving: Option<&ObserverServing>,
    ) -> Vec<CouncilResponse> {
        let mut wire = Vec::new();
        for request in requests {
            write_frame_blocking(&mut wire, request).expect("encode request");
        }
        let mut stream = ScriptedStream {
            input: Cursor::new(wire),
            output: Vec::new(),
        };
        let mut nonce = counting_nonce();
        handle_council_connection(&mut stream, state, observer_serving, &mut nonce);
        let mut reader = stream.output.as_slice();
        let mut responses = Vec::new();
        while let Some(response) =
            read_frame_blocking::<_, CouncilResponse>(&mut reader).expect("read response")
        {
            responses.push(response);
        }
        responses
    }

    fn run_connection(
        requests: &[CouncilRequest],
        state: &CentralizedCustodianState,
    ) -> Vec<CouncilResponse> {
        run_connection_with(requests, state, None)
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
        handle_council_connection(&mut stream, &state, None, &mut counting_nonce());
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
        handle_council_connection(&mut stream, &state, None, &mut counting_nonce());
        assert!(stream.output.is_empty());
    }

    // --- observer fetches ---

    use crate::test_support::{ROOT_KEY, observer_serving, signed_fetch};
    use seismic_council_delivery::ObserverQuery;

    /// The first nonce `counting_nonce` hands out.
    const NONCE_1: [u8; 32] = [1; 32];
    const NONCE_2: [u8; 32] = [2; 32];

    fn assert_observer_rejected(response: &CouncilResponse, code: ObserverRejectCode) {
        assert!(
            matches!(response, CouncilResponse::ObserverRejected { code: c, .. } if *c == code),
            "expected ObserverRejected {{ {code:?} }}, got {response:?}"
        );
    }

    #[test]
    fn challenge_then_signed_fetch_serves_root_key_and_envelopes() {
        let dir = tempfile::tempdir().unwrap();
        let state = build_state(dir.path());
        for epoch in 1..=3u64 {
            state.deliver(&seal(DeliveryPurpose::TxIo, epoch, [epoch as u8; 32]));
        }
        let serving = observer_serving(dir.path());
        let responses = run_connection_with(
            &[
                CouncilRequest::ObserverChallenge,
                signed_fetch(0, &NONCE_1, ObserverQuery::RootKey),
                CouncilRequest::ObserverChallenge,
                signed_fetch(
                    0,
                    &NONCE_2,
                    ObserverQuery::Envelopes {
                        purpose: DeliveryPurpose::TxIo,
                        from_epoch: 2,
                    },
                ),
            ],
            &state,
            Some(&serving),
        );
        assert!(matches!(
            responses[0],
            CouncilResponse::Challenge { nonce } if nonce == NONCE_1
        ));
        let CouncilResponse::RootKey(root) = &responses[1] else {
            panic!("expected root key, got {:?}", responses[1]);
        };
        assert_eq!(root.key, ROOT_KEY);
        let CouncilResponse::Envelopes {
            envelopes,
            delivered_epoch,
        } = &responses[3]
        else {
            panic!("expected envelopes, got {:?}", responses[3]);
        };
        assert_eq!(*delivered_epoch, 3);
        assert_eq!(
            envelopes
                .iter()
                .map(|e| e.payload.epoch)
                .collect::<Vec<_>>(),
            vec![2, 3]
        );
    }

    #[test]
    fn fetch_without_challenge_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let state = build_state(dir.path());
        let serving = observer_serving(dir.path());
        let responses = run_connection_with(
            &[signed_fetch(0, &NONCE_1, ObserverQuery::RootKey)],
            &state,
            Some(&serving),
        );
        assert_observer_rejected(&responses[0], ObserverRejectCode::MissingChallenge);
    }

    /// One challenge authorizes exactly one fetch: replaying a signed fetch
    /// after the nonce was consumed is refused.
    #[test]
    fn nonce_is_single_use() {
        let dir = tempfile::tempdir().unwrap();
        let state = build_state(dir.path());
        let serving = observer_serving(dir.path());
        let fetch = signed_fetch(0, &NONCE_1, ObserverQuery::RootKey);
        let responses = run_connection_with(
            &[CouncilRequest::ObserverChallenge, fetch.clone(), fetch],
            &state,
            Some(&serving),
        );
        assert!(matches!(responses[1], CouncilResponse::RootKey(_)));
        assert_observer_rejected(&responses[2], ObserverRejectCode::MissingChallenge);
    }

    /// A fetch signed over a *previous* nonce doesn't verify against the
    /// current one.
    #[test]
    fn stale_nonce_signature_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let state = build_state(dir.path());
        let serving = observer_serving(dir.path());
        let responses = run_connection_with(
            &[
                CouncilRequest::ObserverChallenge,
                CouncilRequest::ObserverChallenge, // replaces NONCE_1 with NONCE_2
                signed_fetch(0, &NONCE_1, ObserverQuery::RootKey),
            ],
            &state,
            Some(&serving),
        );
        assert_observer_rejected(&responses[2], ObserverRejectCode::BadSignature);
    }

    #[test]
    fn unconfigured_parent_rejects_observer_requests() {
        let dir = tempfile::tempdir().unwrap();
        let state = build_state(dir.path());
        let responses = run_connection_with(
            &[
                CouncilRequest::ObserverChallenge,
                signed_fetch(0, &NONCE_1, ObserverQuery::RootKey),
                CouncilRequest::Ping, // non-observer traffic still works
            ],
            &state,
            None,
        );
        assert_observer_rejected(&responses[0], ObserverRejectCode::NotServingObservers);
        assert_observer_rejected(&responses[1], ObserverRejectCode::NotServingObservers);
        assert!(matches!(responses[2], CouncilResponse::Pong));
    }

    #[test]
    fn tampered_fetch_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let state = build_state(dir.path());
        let serving = observer_serving(dir.path());
        let CouncilRequest::ObserverFetch { request, .. } =
            signed_fetch(0, &NONCE_1, ObserverQuery::RootKey)
        else {
            unreachable!()
        };
        let responses = run_connection_with(
            &[
                CouncilRequest::ObserverChallenge,
                CouncilRequest::ObserverFetch {
                    request,
                    signature: [0u8; 64],
                },
            ],
            &state,
            Some(&serving),
        );
        assert_observer_rejected(&responses[1], ObserverRejectCode::BadSignature);
    }
}
