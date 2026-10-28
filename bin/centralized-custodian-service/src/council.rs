//! HTTP council endpoint, behind a TLS-terminating reverse proxy.
//!
//! POST /v1/council carries one CBOR message (no TCP length prefix). Delivery
//! signatures and observer signatures authorize operations, not connections.
//! Observer challenges are bounded, expiring and atomically consumed across
//! connections, so HTTP pooling/proxying does not weaken replay protection.
//!
//! hyper parses HTTP/1.1 on a dedicated single-threaded tokio runtime; the
//! application dispatch stays synchronous. Only bind this backend to a trusted
//! interface: it bounds concurrent connections, header read time and body
//! bytes, but the fronting proxy must still bound request rates and slow
//! or idle connections beyond those limits.

use crate::{observer_serving::ObserverServing, state::CentralizedCustodianState};
use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper::{
    Method, Request, Response, StatusCode,
    body::Incoming,
    header::{self, HeaderValue},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use seismic_council_delivery::{
    CouncilRequest, CouncilResponse, MAX_ENVELOPES_PER_FETCH, ObserverQuery, ObserverRejectCode,
    ObserverRootKey,
    http::{CBOR_CONTENT_TYPE, COUNCIL_PATH, MAX_BODY_BYTES, decode, encode},
};
use std::{
    collections::HashMap,
    convert::Infallible,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{net::TcpListener, sync::Semaphore};
use tracing::{info, warn};
use zeroize::Zeroizing;

/// Concurrent connections (not just in-flight requests); further accepts
/// wait until one closes. Legitimate peers are the proxy's upstream pool.
const MAX_CONNECTIONS: usize = 64;
/// A client that has not sent a complete request head within this time,
/// including on an idle keep-alive connection, is disconnected.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);
const METRICS_PATH: &str = "/metrics";
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
        crate::metrics::record_council_request(response.kind());
        response
    }

    /// One HTTP exchange. Every non-200 outcome closes the connection without
    /// reading the rest of the request, so a rejected body is never drained.
    pub async fn handle_http(self: Arc<Self>, request: Request<Incoming>) -> HttpResponse {
        // Path and query together, so `/v1/council?x` is not the council path.
        let target = request
            .uri()
            .path_and_query()
            .map_or("", |target| target.as_str());
        if target == METRICS_PATH && request.method() == Method::GET {
            return respond_metrics();
        }
        if target != COUNCIL_PATH {
            return http_error(404);
        }
        if request.method() != Method::POST {
            return http_error(405);
        }
        // This endpoint never upgrades protocols (hyper only does so when
        // asked); refuse requests that ask for one rather than answering them
        // as plain POSTs.
        if request.headers().contains_key(header::UPGRADE)
            || request
                .headers()
                .get_all(header::CONNECTION)
                .iter()
                .any(|v| {
                    v.as_bytes()
                        .to_ascii_lowercase()
                        .windows(7)
                        .any(|w| w == b"upgrade")
                })
        {
            return http_error(400);
        }
        let mut types = request.headers().get_all(header::CONTENT_TYPE).iter();
        if types.next().map(|v| v.as_bytes()) != Some(CBOR_CONTENT_TYPE.as_bytes())
            || types.next().is_some()
        {
            return http_error(415);
        }
        // Declared length first: never start reading a body known to be too
        // large. Chunked bodies are capped while they are read.
        if hyper::body::Body::size_hint(request.body())
            .upper()
            .is_some_and(|len| len > MAX_BODY_BYTES as u64)
        {
            return http_error(413);
        }
        let bytes = match read_body(request.into_body()).await {
            Ok(bytes) => bytes,
            Err(()) => return http_error(413),
        };
        let message = match decode::<CouncilRequest>(&bytes) {
            Ok(message) => message,
            Err(_) => return http_error(400),
        };
        drop(bytes);
        // Dispatch takes locks and persists envelopes; keep it off the
        // single-threaded runtime that parses other connections.
        let handler = self.clone();
        let response = match tokio::task::spawn_blocking(move || handler.dispatch(message)).await {
            Ok(response) => response,
            Err(_) => return http_error(500),
        };
        let bytes = match encode(&response) {
            Ok(bytes) => bytes,
            Err(_) => return http_error(500),
        };
        // Keep the zeroizing allocation as the body's owner (not a plain copy):
        // observer responses carry plaintext root keys and are wiped on drop.
        let mut response = Response::new(Full::new(Bytes::from_owner(bytes)));
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(CBOR_CONTENT_TYPE),
        );
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
    }
}

pub type HttpResponse = Response<Full<Bytes>>;

/// Collect a bounded body; truncated, malformed or oversized input is an error.
async fn read_body(mut body: Incoming) -> Result<Zeroizing<Vec<u8>>, ()> {
    let mut bytes = Zeroizing::new(Vec::new());
    while let Some(frame) = body.frame().await {
        if let Some(data) = frame.map_err(drop)?.data_ref() {
            if bytes.len() + data.len() > MAX_BODY_BYTES {
                return Err(());
            }
            bytes.extend_from_slice(data);
        }
    }
    Ok(bytes)
}

/// `GET /metrics`: Prometheus text exposition. Loopback-only like the rest
/// of the council listener; the response carries counts and labels, never
/// key material.
fn respond_metrics() -> HttpResponse {
    let mut response = Response::new(Full::new(Bytes::from(crate::metrics::render())));
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::CONNECTION, HeaderValue::from_static("close"));
    response
}

fn http_error(status: u16) -> HttpResponse {
    crate::metrics::record_council_http_error(status);
    // No request/response bodies or parser diagnostics in logs/errors.
    let mut response = Response::new(Full::new(Bytes::new()));
    *response.status_mut() = StatusCode::from_u16(status).expect("static status");
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if status == 405 {
        headers.insert(header::ALLOW, HeaderValue::from_static("POST"));
    }
    // hyper honours this by closing the socket after the response instead of
    // draining the unread (attacker-sized) body for keep-alive.
    headers.insert(header::CONNECTION, HeaderValue::from_static("close"));
    response
}

/// Accept loop: one task per connection, bounded by [`MAX_CONNECTIONS`].
/// Runs until the listener fails irrecoverably.
pub async fn serve(listener: TcpListener, handler: Arc<CouncilHandler>) {
    let connections = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let permit = connections
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore never closed");
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(err) => {
                warn!(error = %err, "council accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let handler = handler.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let service = service_fn(move |request| {
                let handler = handler.clone();
                async move { Ok::<_, Infallible>(handler.handle_http(request).await) }
            });
            // Parse errors, timeouts and peer resets end the connection; hyper
            // answers malformed heads itself. Not logged: no parser diagnostics.
            let _ = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(HEADER_READ_TIMEOUT)
                // A client may shut down its write side after a complete
                // request and still expect the response.
                .half_close(true)
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}

/// Blocks the calling thread on a single-threaded runtime serving `listener`.
pub fn serve_council(
    listener: std::net::TcpListener,
    state: Arc<CentralizedCustodianState>,
    observer_serving: Option<Arc<ObserverServing>>,
) {
    let handler = Arc::new(CouncilHandler::new(state, observer_serving));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("council runtime");
    runtime.block_on(async move {
        listener
            .set_nonblocking(true)
            .expect("non-blocking council listener");
        let listener = TcpListener::from_std(listener).expect("council listener");
        if let Ok(address) = listener.local_addr() {
            info!(%address, "council HTTP endpoint listening");
        }
        serve(listener, handler).await
    })
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
