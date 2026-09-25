//! Synchronous HTTP council endpoint, behind a TLS-terminating reverse proxy.
//!
//! POST /v1/council carries one CBOR message (no TCP length prefix). Delivery
//! signatures and observer signatures authorize operations, not connections.
//! Observer challenges are bounded, expiring and atomically consumed across
//! connections, so HTTP pooling/proxying does not weaken replay protection.
//!
//! Only bind this backend to a trusted interface. tiny_http has no configurable
//! per-request socket deadlines or connection cap; the fronting proxy must bound
//! slow/idle connections. We bound body bytes and concurrent application handlers.

use crate::{observer_serving::ObserverServing, state::CentralizedCustodianState};
use seismic_council_delivery::{
    CouncilRequest, CouncilResponse, MAX_ENVELOPES_PER_FETCH, ObserverQuery, ObserverRejectCode,
    ObserverRootKey,
    http::{CBOR_CONTENT_TYPE, COUNCIL_PATH, MAX_BODY_BYTES, decode, encode, read_body},
};
use std::{
    collections::HashMap,
    io::Cursor,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};
use tracing::{info, warn};

const HTTP_WORKERS: usize = 16;
const MAX_CHALLENGES: usize = 1024;
const CHALLENGE_TTL: Duration = Duration::from_secs(30);

#[derive(Default)]
struct Challenges {
    issued: HashMap<[u8; 32], Instant>,
}

impl Challenges {
    fn issue(&mut self, now: Instant, mut random: impl FnMut() -> [u8; 32]) -> Option<[u8; 32]> {
        self.issued
            .retain(|_, issued| now.duration_since(*issued) < CHALLENGE_TTL);
        if self.issued.len() >= MAX_CHALLENGES {
            return None;
        }
        loop {
            let nonce = random();
            if let std::collections::hash_map::Entry::Vacant(entry) = self.issued.entry(nonce) {
                entry.insert(now);
                return Some(nonce);
            }
        }
    }

    fn consume(&mut self, nonce: [u8; 32], now: Instant) -> Option<[u8; 32]> {
        self.issued
            .remove(&nonce)
            .filter(|issued| now.duration_since(*issued) < CHALLENGE_TTL)
            .map(|_| nonce)
    }
}

/// Shared across all HTTP connections; create one handler per custodian process.
pub struct CouncilHandler {
    state: Arc<CentralizedCustodianState>,
    observer_serving: Option<Arc<ObserverServing>>,
    challenges: Mutex<Challenges>,
}

impl CouncilHandler {
    pub fn new(
        state: Arc<CentralizedCustodianState>,
        observer_serving: Option<Arc<ObserverServing>>,
    ) -> Self {
        Self {
            state,
            observer_serving,
            challenges: Mutex::new(Challenges::default()),
        }
    }

    /// Transport-independent authorization and dispatch. Each nonce is removed
    /// under one lock *before* verification; even racing fetches cannot reuse it.
    pub fn dispatch(&self, request: CouncilRequest) -> CouncilResponse {
        self.dispatch_at(request, Instant::now(), random_nonce)
    }

    fn dispatch_at(
        &self,
        request: CouncilRequest,
        now: Instant,
        random: impl FnMut() -> [u8; 32],
    ) -> CouncilResponse {
        let response = match &request {
            CouncilRequest::Ping => CouncilResponse::Pong,
            CouncilRequest::GetStatus => CouncilResponse::Status(self.state.status()),
            CouncilRequest::DeliverEpochKey(envelope) => self.state.deliver(envelope),
            CouncilRequest::ObserverChallenge => match &self.observer_serving {
                None => not_serving_observers(),
                Some(_) => {
                    let nonce = self
                        .challenges
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .issue(now, random);
                    match nonce {
                        Some(nonce) => CouncilResponse::Challenge { nonce },
                        None => rejected(
                            ObserverRejectCode::TooManyChallenges,
                            "challenge limit reached; retry later",
                        ),
                    }
                }
            },
            CouncilRequest::ObserverFetch {
                nonce,
                request,
                signature,
            } => match &self.observer_serving {
                None => not_serving_observers(),
                Some(serving) => {
                    let nonce = self
                        .challenges
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .consume(*nonce, now);
                    match serving.verify_fetch(self.state.network_id(), nonce, request, signature) {
                        Err((code, message)) => rejected(code, message),
                        Ok(()) => match request.query {
                            ObserverQuery::RootKey => CouncilResponse::RootKey(ObserverRootKey {
                                key: serving.root_key(),
                            }),
                            ObserverQuery::Envelopes { from_epoch } => {
                                let (envelopes, delivered_epoch) = self
                                    .state
                                    .envelopes_from(from_epoch, MAX_ENVELOPES_PER_FETCH);
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
        response
    }

    pub fn handle_http(&self, mut request: Request) {
        if request.url() != COUNCIL_PATH {
            return http_error(request, 404);
        }
        if request.method() != &Method::Post {
            return http_error(request, 405);
        }
        // This endpoint never upgrades protocols. tiny_http exposes a raw,
        // unframed body reader when Connection contains "upgrade"; reject that
        // path so peer EOF cannot bypass fixed-length/chunked completeness.
        // Match its substring check, not just well-formed Connection tokens.
        if request.headers().iter().any(|h| {
            h.field.equiv("Upgrade")
                || (h.field.equiv("Connection")
                    && h.value.as_str().to_ascii_lowercase().contains("upgrade"))
        }) {
            return http_error(request, 400);
        }
        let types: Vec<_> = request
            .headers()
            .iter()
            .filter(|h| h.field.equiv("Content-Type"))
            .collect();
        if types.len() != 1 || types[0].value.as_str() != CBOR_CONTENT_TYPE {
            return http_error(request, 415);
        }
        if request
            .body_length()
            .is_some_and(|len| len > MAX_BODY_BYTES)
        {
            return http_error(request, 413);
        }
        let bytes = match read_body(request.as_reader()) {
            Ok(bytes) => bytes,
            Err(_) => return http_error(request, 413),
        };
        let message = match decode::<CouncilRequest>(&bytes) {
            Ok(message) => message,
            Err(_) => return http_error(request, 400),
        };
        drop(bytes);
        let response = self.dispatch(message);
        let bytes = match encode(&response) {
            Ok(bytes) => bytes,
            Err(_) => return http_error(request, 500),
        };
        let length = bytes.len();
        let response = Response::new(
            StatusCode(200),
            vec![
                header("Content-Type", CBOR_CONTENT_TYPE),
                header("Cache-Control", "no-store"),
            ],
            Cursor::new(bytes),
            Some(length),
            None,
        );
        if request.respond(response).is_err() {
            warn!("council HTTP response failed");
        }
    }
}

fn header(name: &str, value: &str) -> Header {
    Header::from_bytes(name, value).expect("static HTTP header")
}

fn http_error(request: Request, status: u16) {
    // No request/response bodies or parser diagnostics in logs/errors.
    let mut response =
        Response::empty(StatusCode(status)).with_header(header("Cache-Control", "no-store"));
    if status == 405 {
        response.add_header(header("Allow", "POST"));
    }
    // The locally patched API shuts down the socket before dropping unread
    // body readers. A Connection header alone is ignored by upstream tiny_http,
    // whose rejection cleanup otherwise drains attacker-controlled body lengths.
    let _ = request.respond_and_close(response);
}

/// Fixed-size application worker pool; tiny_http handles HTTP parsing.
pub fn serve_council(
    server: Server,
    state: Arc<CentralizedCustodianState>,
    observer_serving: Option<Arc<ObserverServing>>,
) {
    info!(address = %server.server_addr(), "council HTTP endpoint listening");
    let handler = CouncilHandler::new(state, observer_serving);
    std::thread::scope(|scope| {
        for _ in 0..HTTP_WORKERS {
            scope.spawn(|| {
                for request in server.incoming_requests() {
                    handler.handle_http(request);
                }
            });
        }
    });
}

fn random_nonce() -> [u8; 32] {
    use rand::RngCore as _;
    let mut nonce = [0u8; 32];
    rand::rng().fill_bytes(&mut nonce);
    nonce
}

fn rejected(code: ObserverRejectCode, message: &str) -> CouncilResponse {
    CouncilResponse::ObserverRejected {
        code,
        message: message.to_string(),
    }
}

fn not_serving_observers() -> CouncilResponse {
    rejected(
        ObserverRejectCode::NotServingObservers,
        "this custodian has no summit key dir and does not serve observers",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{
        EPOCH_ROOT, ROOT_KEY, build_state, observer_serving, seal, signed_fetch,
    };

    const NONCE: [u8; 32] = [1; 32];

    fn handler(dir: &std::path::Path, observers: bool) -> CouncilHandler {
        CouncilHandler::new(
            Arc::new(build_state(dir)),
            observers.then(|| Arc::new(observer_serving(dir))),
        )
    }

    fn assert_rejected(response: CouncilResponse, expected: ObserverRejectCode) {
        assert!(
            matches!(response, CouncilResponse::ObserverRejected { code, .. } if code == expected)
        );
    }

    #[test]
    fn ping_status_delivery_and_idempotent_retry() {
        let dir = tempfile::tempdir().unwrap();
        let handler = handler(dir.path(), false);
        assert!(matches!(
            handler.dispatch(CouncilRequest::Ping),
            CouncilResponse::Pong
        ));
        assert!(
            matches!(handler.dispatch(CouncilRequest::GetStatus), CouncilResponse::Status(s) if s.epoch == 0)
        );
        let delivery = CouncilRequest::DeliverEpochKey(seal(1, EPOCH_ROOT));
        assert!(matches!(
            handler.dispatch(delivery.clone()),
            CouncilResponse::Delivered { epoch: 1 }
        ));
        assert!(matches!(
            handler.dispatch(delivery),
            CouncilResponse::AlreadyDelivered { epoch: 1 }
        ));
        assert!(
            matches!(handler.dispatch(CouncilRequest::GetStatus), CouncilResponse::Status(s) if s.epoch == 1)
        );
    }

    #[test]
    fn root_and_envelopes_need_fresh_signed_challenges() {
        let dir = tempfile::tempdir().unwrap();
        let handler = handler(dir.path(), true);
        for epoch in 1..=3 {
            handler.dispatch(CouncilRequest::DeliverEpochKey(seal(epoch, EPOCH_ROOT)));
        }
        let now = Instant::now();
        for query in [
            ObserverQuery::RootKey,
            ObserverQuery::Envelopes { from_epoch: 2 },
        ] {
            handler.dispatch_at(CouncilRequest::ObserverChallenge, now, || NONCE);
            let fetch = signed_fetch(0, &NONCE, query.clone());
            let response = handler.dispatch_at(fetch.clone(), now, random_nonce);
            match query {
                ObserverQuery::RootKey => assert!(
                    matches!(response, CouncilResponse::RootKey(root) if root.key == ROOT_KEY)
                ),
                ObserverQuery::Envelopes { .. } => {
                    let CouncilResponse::Envelopes {
                        envelopes,
                        delivered_epoch,
                    } = response
                    else {
                        panic!("expected envelopes")
                    };
                    assert_eq!(delivered_epoch, 3);
                    assert_eq!(
                        envelopes
                            .iter()
                            .map(|e| e.payload.epoch)
                            .collect::<Vec<_>>(),
                        vec![2, 3]
                    );
                }
            }
            assert_rejected(
                handler.dispatch_at(fetch, now, random_nonce),
                ObserverRejectCode::MissingChallenge,
            );
        }
    }

    #[test]
    fn missing_expired_and_tampered_challenges_fail() {
        let dir = tempfile::tempdir().unwrap();
        let handler = handler(dir.path(), true);
        let now = Instant::now();
        let fetch = signed_fetch(0, &NONCE, ObserverQuery::RootKey);
        assert_rejected(
            handler.dispatch_at(fetch.clone(), now, random_nonce),
            ObserverRejectCode::MissingChallenge,
        );
        handler.dispatch_at(CouncilRequest::ObserverChallenge, now, || NONCE);
        assert_rejected(
            handler.dispatch_at(fetch.clone(), now + CHALLENGE_TTL, random_nonce),
            ObserverRejectCode::MissingChallenge,
        );
        handler.dispatch_at(CouncilRequest::ObserverChallenge, now, || NONCE);
        let CouncilRequest::ObserverFetch { nonce, request, .. } = fetch.clone() else {
            unreachable!()
        };
        assert_rejected(
            handler.dispatch_at(
                CouncilRequest::ObserverFetch {
                    nonce,
                    request,
                    signature: [0; 64],
                },
                now,
                random_nonce,
            ),
            ObserverRejectCode::BadSignature,
        );
        // Even a failed attempt consumes its challenge.
        assert_rejected(
            handler.dispatch_at(fetch, now, random_nonce),
            ObserverRejectCode::MissingChallenge,
        );
    }

    #[test]
    fn challenge_is_consumed_atomically_under_concurrent_replay() {
        let dir = tempfile::tempdir().unwrap();
        let handler = handler(dir.path(), true);
        handler.dispatch_at(CouncilRequest::ObserverChallenge, Instant::now(), || NONCE);
        let barrier = std::sync::Barrier::new(8);
        let successes = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        matches!(
                            handler.dispatch(signed_fetch(0, &NONCE, ObserverQuery::RootKey)),
                            CouncilResponse::RootKey(_)
                        )
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| usize::from(h.join().unwrap()))
                .sum::<usize>()
        });
        assert_eq!(successes, 1);
    }

    #[test]
    fn challenge_store_is_bounded_and_recovers_after_expiry() {
        let mut challenges = Challenges::default();
        let now = Instant::now();
        for index in 0..MAX_CHALLENGES {
            let mut nonce = [0; 32];
            nonce[..8].copy_from_slice(&(index as u64).to_be_bytes());
            assert!(challenges.issue(now, || nonce).is_some());
        }
        assert!(challenges.issue(now, || [255; 32]).is_none());
        assert!(
            challenges
                .issue(now + CHALLENGE_TTL, || [255; 32])
                .is_some()
        );
        assert_eq!(challenges.issued.len(), 1);
    }

    #[test]
    fn unconfigured_parent_refuses_observer_operations() {
        let dir = tempfile::tempdir().unwrap();
        let handler = handler(dir.path(), false);
        assert_rejected(
            handler.dispatch(CouncilRequest::ObserverChallenge),
            ObserverRejectCode::NotServingObservers,
        );
        assert_rejected(
            handler.dispatch(signed_fetch(0, &NONCE, ObserverQuery::RootKey)),
            ObserverRejectCode::NotServingObservers,
        );
    }
}
