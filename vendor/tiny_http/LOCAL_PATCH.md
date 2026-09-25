# Local tiny_http security patch

## Provenance

Vendored from the crates.io **tiny_http 0.12.0** release:

- Repository: https://github.com/tiny-http/tiny-http
- Release VCS revision: `212b1c45852fef2093dc1374875a9393c55eb4b9`
- Crate SHA-256: `389915df6413a2e74fb181895f933386023c71110878cd0825588928e64cdc82`
- License: MIT OR Apache-2.0 (both upstream license files retained).
- `Cargo.toml` is the upstream `Cargo.toml.orig`; source, tests and README are
  retained. Release metadata, examples and benchmarks are not needed here.

The workspace pins `=0.12.0` and uses `[patch.crates-io]` to select this copy.
Do not remove the patch on a dependency update until equivalent upstream
behavior passes the regression tests below. The custodian enables no TLS features.

## Changes

1. `EqualReader::drop` uses a fixed 8 KiB stack buffer instead of allocating
   the unread `Content-Length`. The length is attacker-controlled, even when
   the application has already returned HTTP 413.
2. New **`Request::respond_and_close`** emits `Connection: close`, flushes the
   response, then shuts down both directions of the underlying socket, even
   if writing the response failed. Shutdown happens before releasing the
   sequential writer or dropping the unread body reader.
3. Each connection has a shared cancellation flag and a separate raw socket
   handle. Body readers and the header parser stop consuming buffered input
   after cancellation, so a rejected body's remainder cannot be parsed as
   another request. The socket handle also allows cancellation without taking
   a TLS/reader/writer lock. Normal `respond` retains keep-alive semantics.
4. Dropping an unanswered request uses the same close path for its automatic
   HTTP 500 response.
5. Unsupported HTTP versions are rejected immediately after the request line,
   before constructing a request or buffering its body. The parser sends an
   HTTP/1.1 505 response, flushes and closes using the one available sequential
   writer. Upstream allocated a second writer while retaining the first in its
   request, causing a circular channel wait that survived peer disconnection.
6. `EqualReader::read` returns `UnexpectedEof` when fixed-length body data is
   truncated. A `ChunkedSource` adapter likewise rejects underlying EOF before
   the chunk decoder has recognized the terminating chunk. This prevents a
   complete CBOR prefix in an incomplete HTTP body from reaching dispatch.
   Empty-buffer reads and correctly framed keep-alive messages remain valid.

The cancellation plumbing is in `connection.rs`, `client.rs`, `request.rs`
and `lib.rs`; only paths that explicitly close the socket may add the close
header in `response.rs`. Like upstream, ordinary `Response::with_header("Connection",
"close")` is still ignored: emitting the header without actually closing
would recreate the misleading fixture behavior.

## Verification

From the workspace root:

```sh
cargo test -p seismic-centralized-custodian-service --test http_rejection
cargo test -p seismic-centralized-custodian-service --test http_observer
cargo test -p seismic-council-delivery --features cli --test http_cli
```

The Linux rejection tests spawn the **actual custodian binary**, with a
512 MiB address-space limit, disabled core dumps, temporary state and an
OS-selected loopback port. They send header-only enormous lengths, other
incomplete rejected bodies, an unfinished oversized chunk and malformed
chunk input. They require the final status **and socket EOF**, retain client
write sides across more requests than the worker count, and verify that
both HTTP and Unix IPC remain healthy. Child processes are killed and reaped
even on assertion failure.

Observer and CLI fixtures use the explicit close API and assert distinct
accepted TCP peer endpoints across challenge/fetch and batch/page requests.
The `EqualReader` unit test also checks a `usize::MAX` length with an EOF
reader, without allocating that length.

Additional regressions require HTTP 505 plus EOF for repeated textual
`HTTP/2.0` and `HTTP/3.0` requests (including withheld small bodies), and check
that `/proc` thread/FD counts recover. Signed deliveries sent inside truncated
fixed-length/chunked bodies must return a rejection without dispatch, epoch
advancement or a persisted envelope. The identical signed delivery must succeed
with complete framing. The council application also rejects protocol upgrades:
upstream intentionally bypasses normal HTTP body framing for upgrade requests,
so this unsupported path must not reach council dispatch. Library unit tests
cover premature EOF, missing chunk terminators, empty reads and preservation of
bytes belonging to the next request.

## Remaining limits

This is not a general HTTP hardening fork. It does not add connection caps,
header/chunk-metadata limits, a bounded parser queue, or socket deadlines.
The fronting proxy must still enforce size, connection, timeout and request
rate limits, and the backend must remain private. Normal `respond` still
allows bounded-buffer draining; rejecting callers must use
`respond_and_close`. The close API flushes before shutdown, so the proxy's
response/write timeout remains necessary as well.
