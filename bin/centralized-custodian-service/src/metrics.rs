//! Prometheus metrics, served as `GET /metrics` on the council listener.
//!
//! The council listener is loopback-only, so the node's Prometheus Agent can
//! scrape it like Reth's and Summit's endpoints without exposing anything
//! new. Labels use the protocol's stable `kind()`/`method()` strings, which
//! are payload-free by design; no key material, nonce, or peer identity is
//! ever recorded.
//!
//! | Metric                                              | Type    | Meaning                                                      |
//! | --------------------------------------------------- | ------- | ------------------------------------------------------------ |
//! | `custodian_delivered_epoch`                         | gauge   | highest epoch whose root key the council has delivered (0 = none) |
//! | `custodian_council_requests_total{outcome}`         | counter | council HTTP requests by response kind (`delivered`, `rejected`, …) |
//! | `custodian_council_http_errors_total{status}`       | counter | council requests refused before parsing, by HTTP status     |
//! | `custodian_socket_requests_total{request,response}` | counter | Unix-socket requests from Reth by request and response kind |
//! | `custodian_build_info{version,role}`                | gauge   | always 1; `role` is `validator` or `observer`                |
//!
//! `custodian_delivered_epoch` not advancing when the council has rotated is
//! the alert that matters; `socket_requests_total{response="epoch_key_unavailable"}`
//! rising means Reth is asking for an epoch this node has not received.
//!
//! # Allocation-free request paths
//!
//! Every counter a request path can touch is created once in [`init`] and
//! looked up from a table, so recording is an atomic increment with no
//! allocation. Rejected requests must not allocate (that is part of the
//! security boundary `tests/http_rejection.rs` checks), and a first write to
//! a label set the registry has not seen would. Unknown labels (a protocol
//! addition this table has not caught up with) still count, via the
//! allocating path, rather than being dropped.

use metrics::{Counter, counter, describe_counter, describe_gauge, gauge};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::collections::HashMap;
use std::sync::OnceLock;

static HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();
static SOCKET_COUNTERS: OnceLock<HashMap<(&'static str, &'static str), Counter>> = OnceLock::new();
static COUNCIL_COUNTERS: OnceLock<HashMap<&'static str, Counter>> = OnceLock::new();
static COUNCIL_HTTP_ERROR_COUNTERS: OnceLock<HashMap<u16, Counter>> = OnceLock::new();

/// `seismic_custodian_ipc::Request::method()` values.
const SOCKET_REQUESTS: [&str; 7] = [
    "ping",
    "get_tx_io_keypair",
    "get_tx_io_public_key",
    "get_rng_ikm",
    "get_snapshot_key",
    "create_root_key_bootstrap_attempt",
    "wrap_root_key",
];
/// `seismic_custodian_ipc::Response::kind()` values.
const SOCKET_RESPONSES: [&str; 13] = [
    "pong",
    "tx_io_keypair",
    "tx_io_public_key",
    "rng_ikm",
    "snapshot_key",
    "root_key_bootstrap_attempt_created",
    "wrapped_root_key",
    "root_key_installed",
    "root_key_already_present",
    "root_key_absent",
    "epoch_key_unavailable",
    "denied",
    "error",
];
/// `CouncilResponse::kind()` values.
const COUNCIL_OUTCOMES: [&str; 9] = [
    "pong",
    "status",
    "delivered",
    "already_delivered",
    "rejected",
    "challenge",
    "root_key",
    "envelopes",
    "observer_rejected",
];
/// Statuses `council::http_error` is called with.
const COUNCIL_HTTP_ERRORS: [u16; 6] = [400, 404, 405, 413, 415, 500];

/// Install the global recorder and pre-create every counter. Idempotent.
pub fn init(role: &'static str) -> PrometheusHandle {
    HANDLE
        .get_or_init(|| {
            let handle = PrometheusBuilder::new()
                .install_recorder()
                .expect("install Prometheus recorder");
            describe_gauge!(
                "custodian_delivered_epoch",
                "Highest epoch whose root key the council has delivered (0 = none)"
            );
            describe_counter!(
                "custodian_council_requests_total",
                "Council HTTP requests by response kind"
            );
            describe_counter!(
                "custodian_council_http_errors_total",
                "Council HTTP requests refused before parsing, by status"
            );
            describe_counter!(
                "custodian_socket_requests_total",
                "Unix-socket requests by request and response kind"
            );
            describe_gauge!(
                "custodian_build_info",
                "Always 1; carries version and role labels"
            );
            gauge!(
                "custodian_build_info",
                "version" => env!("CARGO_PKG_VERSION"),
                "role" => role
            )
            .set(1.0);
            gauge!("custodian_delivered_epoch").set(0.0);

            let mut socket = HashMap::new();
            for request in SOCKET_REQUESTS {
                for response in SOCKET_RESPONSES {
                    socket.insert(
                        (request, response),
                        counter!(
                            "custodian_socket_requests_total",
                            "request" => request,
                            "response" => response
                        ),
                    );
                }
            }
            let _ = SOCKET_COUNTERS.set(socket);
            let _ = COUNCIL_COUNTERS.set(
                COUNCIL_OUTCOMES
                    .into_iter()
                    .map(|outcome| {
                        (
                            outcome,
                            counter!("custodian_council_requests_total", "outcome" => outcome),
                        )
                    })
                    .collect(),
            );
            let _ = COUNCIL_HTTP_ERROR_COUNTERS.set(
                COUNCIL_HTTP_ERRORS
                    .into_iter()
                    .map(|status| {
                        (
                            status,
                            counter!(
                                "custodian_council_http_errors_total",
                                "status" => status.to_string()
                            ),
                        )
                    })
                    .collect(),
            );
            handle
        })
        .clone()
}

/// Render the current metrics in Prometheus text format.
pub fn render() -> String {
    match HANDLE.get() {
        Some(handle) => handle.render(),
        None => String::new(),
    }
}

pub fn set_delivered_epoch(epoch: u64) {
    gauge!("custodian_delivered_epoch").set(epoch as f64);
}

pub fn record_council_request(outcome: &'static str) {
    match COUNCIL_COUNTERS.get().and_then(|m| m.get(outcome)) {
        Some(counter) => counter.increment(1),
        None => counter!("custodian_council_requests_total", "outcome" => outcome).increment(1),
    }
}

pub fn record_council_http_error(status: u16) {
    match COUNCIL_HTTP_ERROR_COUNTERS
        .get()
        .and_then(|m| m.get(&status))
    {
        Some(counter) => counter.increment(1),
        None => counter!("custodian_council_http_errors_total", "status" => status.to_string())
            .increment(1),
    }
}

pub fn record_socket_request(request: &'static str, response: &'static str) {
    match SOCKET_COUNTERS
        .get()
        .and_then(|m| m.get(&(request, response)))
    {
        Some(counter) => counter.increment(1),
        None => counter!(
            "custodian_socket_requests_total",
            "request" => request,
            "response" => response
        )
        .increment(1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seismic_council_delivery::CouncilResponse;
    use seismic_custodian_ipc::{Request, Response};

    // The recorder is process-global and shared by every test in this
    // binary, so these check presence and shape, not exact counts.

    #[test]
    fn renders_recorded_values_without_payloads() {
        init("validator");
        set_delivered_epoch(3);
        record_council_request("delivered");
        record_council_http_error(405);
        record_socket_request("get_tx_io_keypair", "tx_io_keypair");
        record_socket_request("get_rng_ikm", "epoch_key_unavailable");
        let out = render();
        // Exact value is checked in tests/http_server.rs; here the state
        // tests' deliveries race with this one for the same gauge.
        assert!(out.contains("\ncustodian_delivered_epoch "), "{out}");
        assert!(
            out.contains("# TYPE custodian_delivered_epoch gauge"),
            "{out}"
        );
        assert!(
            out.contains("custodian_council_requests_total{outcome=\"delivered\"} "),
            "{out}"
        );
        assert!(
            out.contains("custodian_council_http_errors_total{status=\"405\"} "),
            "{out}"
        );
        assert!(
            out.contains("request=\"get_rng_ikm\",response=\"epoch_key_unavailable\"} "),
            "{out}"
        );
        assert!(
            out.contains("custodian_build_info{") && out.contains("role=\"validator\""),
            "{out}"
        );
    }

    /// Every label a request path can produce must have a pre-built counter,
    /// or the hot path allocates (see the module docs).
    #[test]
    fn counter_tables_cover_the_protocol() {
        init("validator");
        let socket = SOCKET_COUNTERS.get().unwrap();
        for request in SOCKET_REQUESTS {
            for response in SOCKET_RESPONSES {
                assert!(
                    socket.contains_key(&(request, response)),
                    "{request}/{response}"
                );
            }
        }
        let council = COUNCIL_COUNTERS.get().unwrap();
        for outcome in COUNCIL_OUTCOMES {
            assert!(council.contains_key(outcome), "{outcome}");
        }
        let errors = COUNCIL_HTTP_ERROR_COUNTERS.get().unwrap();
        for status in COUNCIL_HTTP_ERRORS {
            assert!(errors.contains_key(&status), "{status}");
        }
        // Spot-check against the real accessors so a renamed variant upstream
        // fails here instead of silently falling back to the allocating path.
        assert!(SOCKET_REQUESTS.contains(&Request::Ping.method()));
        assert!(SOCKET_RESPONSES.contains(&Response::Pong.kind()));
        assert!(
            SOCKET_RESPONSES.contains(
                &Response::Denied {
                    message: String::new()
                }
                .kind()
            )
        );
        assert!(SOCKET_RESPONSES.contains(&Response::EpochKeyUnavailable { epoch: 1 }.kind()));
        assert!(COUNCIL_OUTCOMES.contains(&CouncilResponse::Pong.kind()));
    }
}
