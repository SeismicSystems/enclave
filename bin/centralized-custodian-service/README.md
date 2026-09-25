# seismic-centralized-custodian-service

The custodian for the network's **centralized phase**, before custody moves
to decentralized TEEs. It runs standalone — no attestation service, no
tdx-init, no setup-persistent-luks — and serves the same Unix-socket API as
`seismic-custodian-service`, with one difference: at epochs `>= 1` the ROOT
key itself rotates. Each rotation is **one 32-byte root key signed by a
security council's Ethereum wallet** delivered over HTTP, and every purpose
key of that epoch (tx-io, rng, snapshot) is HKDF-derived from the delivered
root. An undelivered epoch answers `EpochKeyUnavailable`, never a derivation
from an earlier root. Epoch 0 uses the local keyfile and the TDX custodian's
HKDF paths. The attested root-key bootstrap methods are unavailable here.

An **observer custodian** fetches the epoch-0 root and council-delivered
envelopes from its parent at boot and on demand. The council delivers to
validator custodians; correctly configured observers sync from their parents.

## HTTP transport and confidentiality

The backend is synchronous `tiny_http`, with no TLS features and no async
runtime. It defaults to **`127.0.0.1:7876`** and exposes:

```http
POST /v1/council
Content-Type: application/cbor
Accept: application/cbor
```

Each body is exactly one `CouncilRequest` or `CouncilResponse` encoded as
CBOR, **without** the Unix socket's four-byte length prefix. The body limit
is 64 KiB in both directions. The methods are `Ping`, `GetStatus`,
`DeliverEpochKey`, `ObserverChallenge`, and `ObserverFetch`. Valid protocol
replies, including typed delivery/observer rejections, return HTTP 200.
Transport errors use 400 (invalid CBOR or unsupported protocol upgrade), 404
(path), 405 (method), 413 (body limit/read failure, including premature EOF),
415 (content type), or 500 (response encoding failure). Unsupported HTTP versions
are rejected by the parser with HTTP/1.1 505 and connection closure.
Responses carry `Cache-Control: no-store`; no keys belong in URLs or logs.
Transport errors close the connection without draining an unread body.

The workspace uses a pinned, locally patched `tiny_http` (see
[`vendor/tiny_http/LOCAL_PATCH.md`](../../vendor/tiny_http/LOCAL_PATCH.md)).
Upstream 0.12.0 allocates from an unread `Content-Length` when dropping a
rejected request, even after HTTP 413, and ignores response-side
`Connection: close` headers. The patch bounds cleanup buffers and provides
an explicit respond-and-close API that cancels body reads and closes the
socket before request destruction. It also rejects unsupported HTTP versions
without leaking parser tasks, and treats truncated fixed-length/chunked bodies
as errors rather than complete messages. The council endpoint rejects protocol
upgrades so their raw-reader path cannot bypass framing checks. Do not substitute
the unpatched crate.

**Delivery envelopes and observer responses contain plaintext root keys.**
Serve the backend through an HTTPS reverse proxy, or use a secure tunnel.
Do not expose the HTTP backend to untrusted networks. TLS authenticates the
server and encrypts the transport; council and observer signatures authorize
individual operations. HTTP itself adds no encryption. Proxy configuration
is outside this repository's scope.

Clients accept an **HTTPS base URL** with an optional proxy path prefix:

```text
https://node.example.com/custodian
    -> POST https://node.example.com/custodian/v1/council
```

The proxy must strip its prefix before forwarding to `/v1/council`. Plain
`http://` is accepted only for loopback hosts (`localhost`, `127.0.0.0/8`,
`::1`), for local access or secure tunnels. Bare `host:port`, `tcp://`, and
`tls://` are no longer accepted. Credentials, query parameters, and fragments
in base URLs are rejected.

The shared synchronous HTTPS client uses `ureq`/Rustls, validates certificates,
does not follow redirects, and ignores environment proxy settings. Each
exchange has a 5-second connect timeout and a 10-second overall timeout,
including the response body. Compression is not enabled. The HTTP client
is feature-gated in `seismic-council-delivery`; both the CLI and observer
custodian use it. The custodian's **server** remains TLS-free.

The application has 16 HTTP workers and a bounded challenge store. Unlike
the old raw TCP server, **tiny_http does not expose socket deadlines or a
connection cap**. The fronting proxy must bound idle/slow connections,
request duration, connection count, request/header sizes and request rates.
A worker cap is not a network connection cap. Unauthenticated challenge
issuance also needs access/rate controls: a bounded nonce store limits memory,
not an attacker's ability to exhaust its slots. Keep the backend loopback-only
and prevent the proxy from caching, logging, or spilling secret bodies to
temporary files.

## State on disk

Two things persist, both under `/var/lib/seismic/custodian/` by default:

- **Root keyfile** (`--root-key-file`, 32 raw bytes, mode 0600). If absent
  at first boot, a **publicly known shared default** is pinned there so all
  nodes agree on epoch-0 keys. Epoch 0 then provides **no confidentiality**;
  deliver epoch 1 promptly. To use a secret epoch-0 root, pre-place the same
  securely provisioned 32 bytes on the network's custodians.
- **Delivery envelopes** (`--delivery-dir`, `<epoch>.cbor`, directory 0700,
  files 0600). Accepted envelopes are persisted durably **before** the epoch
  becomes observable. These files contain plaintext epoch roots. Every boot
  re-verifies their council signatures. A corrupt file stops loading at the
  last good epoch; redelivering the missing epoch heals the gap.

An unusable delivery directory or malformed keyfile fails startup. Protect
and back up both the root keyfile and envelope archive.

## Council CLI and fleet delivery

Build the ceremony tool:

```bash
cargo build --release -p seismic-council-delivery --features cli --bin council-signer
```

It provides `gen-key`, `status`, `typed-data`, `deliver`, and `deliver-batch`.
Targets are either `--node <base-url>` or `--nodes-file <path>`:

```toml
# fleet.toml: validator custodians' HTTPS base URLs, not Reth RPC URLs.
nodes = [
    "https://node-1.example.com/custodian",
    "https://node-2.example.com/custodian",
]
```

```bash
council-signer status --nodes-file fleet.toml
```

Check the reported next-delivery epoch and select the correct chain ID.
The custodian's delivered-epoch counter is **not** the active on-chain epoch.
For example, for a fresh epoch-1 delivery (replace the chain ID):

```bash
set +x
umask 077
export SEISMIC_CHAIN_ID=5124
EPOCH=1
mkdir -p council-private
chmod 700 council-private

# Generate once; refuse to overwrite an existing epoch key.
(set -o noclobber; council-signer gen-key > "council-private/${EPOCH}.key")
# Stop if generation failed or the file already exists; investigate before proceeding.
export COUNCIL_ROOT_KEY="$(< "council-private/${EPOCH}.key")"

council-signer typed-data --epoch "$EPOCH" > "council-private/${EPOCH}.json"
SIGNATURE="$(scast wallet sign --data --from-file --interactive "council-private/${EPOCH}.json")"
unset COUNCIL_SIGNER_KEY
council-signer deliver --nodes-file fleet.toml --epoch "$EPOCH" \
  --signature "$SIGNATURE" --save-dir council-private/envelopes
unset COUNCIL_ROOT_KEY
council-signer status --nodes-file fleet.toml
```

The interactive prompt is for the **council signing wallet**, not the new
epoch root. It must match `--council-address`, an EOA (EIP-1271 contract
wallets are not supported). It need not be the on-chain rotation admin.
The wallet signs EIP-712 `RootKeyDelivery(uint64 epoch,bytes32 keyCommitment)`;
only the root's keccak-256 commitment is shown to the wallet. The network
identifier derived from `--chain-id` scopes the signature against cross-chain
replay. `--council-key` / `COUNCIL_SIGNER_KEY` is an alternative to an external
signature, not something to combine with `--signature`.

`--save-dir` (or `COUNCIL_ENVELOPE_DIR`) saves the signed envelope **before**
network delivery, with private permissions. Fleet delivery validates all
URLs first, attempts every node, and exits nonzero if any fail. Successful
nodes are not rolled back. Retry the **same** envelope/root, never generate
a different root for an already delivered epoch:

```bash
council-signer deliver-batch --nodes-file fleet.toml \
  --envelope-dir council-private/envelopes
```

Batch delivery asks each node for its current epoch and replays missing
envelopes in sequence. Retain the complete archive for later joining nodes.
The signature and envelope storage formats are unchanged by HTTP.

Epochs are sequential; the first delivery is epoch 1. Identical envelope
redelivery is idempotent (`AlreadyDelivered`); conflicting material at an
existing epoch is rejected. Root derivation is validated before installation.
Once delivery readiness is verified, separately announce the matching epoch's
activation block on chain. **Delivering a root does not activate it.**

## Observer custodians

A summit observer holds a copy of its parent's master `node_key.pem`.
`--summit-key-dir` enables parent-side observer serving; only the master
public key is retained for signature checks. Any correctly derived child
index can authenticate. Observer mode additionally requires `--observer
<index>` and `--parent-custodian <https-base-url>`.

At boot the observer fetches the parent's epoch-0 root, persists it, and
backfills signed envelopes. An existing local root that disagrees with the
parent is boot-fatal. If the parent is unavailable but a local root exists,
startup retains that local root and warns. An observer never installs the
public default root. Missing epochs trigger bounded HTTP fetches from the
parent before returning `EpochKeyUnavailable`.

Each fetch uses two independent HTTP requests:

1. `ObserverChallenge` returns a random nonce.
2. `ObserverFetch { nonce, request, signature }` returns that nonce and an
   Ed25519 signature over `domain || nonce || request` from the derived child.

Nonces are process-wide, expire after 30 seconds, and are removed atomically
before verification. Each authorizes at most one attempt, including across
connections and concurrent replays. The store caps outstanding challenges at
1,024 (`TooManyChallenges` on exhaustion); expired entries are reclaimed on
issuance. Proxies need not preserve TCP affinity, but requests must reach the
same custodian instance, not be balanced among independent custodians.

Fetched envelopes always pass local council verification and durable storage.
The epoch-0 root has no council signature: authenticated HTTPS to the intended
parent (or a correctly configured secure tunnel) is therefore essential.

## Migration and validation

This is a coordinated wire-protocol migration; there is **no raw-TCP fallback**.
Update the custodian, `council-signer`, observer parent URLs, fleet URLs and
HTTP proxy routing together. The old `tls://` scheme described raw CBOR over
TLS, not HTTPS. Reth's Unix socket, derivation rules, signed envelopes,
on-disk archives and on-chain registry remain unchanged.

Tests include real CLI processes against HTTP fixtures, captured observer
requests with a proxy prefix and asserted connection changes, server validation,
replay/expiry/concurrency tests, error/redirect/body-limit/deadline handling,
and HTTP delivery followed by key retrieval through the real Unix socket.
Linux rejection regressions run the actual binary under an address-space
limit, require socket closure for incomplete/oversized requests, and verify
continued HTTP and Unix-socket availability. Additional regressions check
parser thread/FD recovery after unsupported HTTP versions, and verify that
truncated signed deliveries (including upgrade attempts) cannot dispatch, advance
the epoch or persist an envelope; complete copies of the same deliveries succeed:

```bash
cargo test -p seismic-council-delivery --features cli
cargo test -p seismic-centralized-custodian-service
```

## Flags

| flag | env | default |
|---|---|---|
| `--socket` | — | `/run/seismic/custodian/custodian.sock` |
| `--root-key-file` | `SEISMIC_ROOT_KEY_FILE` | `/var/lib/seismic/custodian/root.key` |
| `--allow USER:PURPOSES` (repeatable) | — | deny-all |
| `--council-listen` | `SEISMIC_COUNCIL_LISTEN_ADDR` | `127.0.0.1:7876` (HTTP backend) |
| `--council-address` (required) | `SEISMIC_COUNCIL_ADDRESS` | — |
| `--chain-id` (required) | `SEISMIC_CHAIN_ID` | — |
| `--delivery-dir` | — | `/var/lib/seismic/custodian/deliveries` |
| `--summit-key-dir` | `SEISMIC_SUMMIT_KEY_DIR` | — |
| `--observer INDEX` | — | — |
| `--parent-custodian URL` | — | — (HTTPS base URL; HTTP only on loopback) |

Like the TDX custodian, this binary links no async runtime. Build it separately:
Cargo feature unification with IPC async-client consumers can otherwise pull
Tokio into the binary (see `crates/custodian-ipc/Cargo.toml`). Rotating the
council signing address invalidates verification of archived envelopes unless
they are re-signed and redelivered under the new authority.
