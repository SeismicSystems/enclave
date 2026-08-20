# seismic-centralized-custodian-service

The custodian for the network's **centralized phase**, before custody moves
to decentralized TEEs. It runs standalone — no attestation service, no
tdx-init, no setup-persistent-luks — and serves the same Unix-socket API as
`seismic-custodian-service`, with one difference: purpose keys at epochs
`>= 1` are not derived from the root key. They arrive as **deliveries signed
by a security council's Ethereum wallet** over a TCP port, and asking for an
epoch the council has not delivered answers the typed `EpochKeyUnavailable`
error instead of deriving — making the council the network's actual rotation
authority.

Epoch-0 derivations use the same HKDF paths as the TDX custodian, so
consumers see identical bytes when the network later migrates. The root-key
bootstrap methods answer a stable error: there is no attested bootstrap
here.

## Transport security is the deployment's job

Delivery envelopes carry the purpose key **in plaintext** under the council
signature. This service deliberately contains no TLS and no envelope
encryption: the centralized phase runs among known operators, who must front
the council port with a TLS terminator or tunnel (nginx, WireGuard, SSH —
whatever the ops stack uses) so key material is never plaintext on an
untrusted wire. The port itself must never be reachable directly from
untrusted networks.

## State on disk

Two things persist, both under `/var/lib/seismic/custodian/` by default:

- **The root keyfile** (`--root-key-file`, 32 raw bytes, mode 0600). If
  absent at first boot, the **publicly known shared default** (a hash of a
  fixed label in `root_key_file.rs`) is pinned there, so every node agrees
  on epoch-0 keys with zero coordination. The trade is explicit: epoch 0
  provides **no confidentiality** — treat it as a placeholder and have the
  council deliver epoch 1 immediately after launch (the service warns on
  every boot while the default is in use). An operator who wants a secret
  root key pre-places 32 random bytes before first boot.
- **Delivery envelopes** (`--delivery-dir`, `<purpose>/<epoch>.cbor`, dirs
  0700 / files 0600): accepted deliveries stored verbatim, written durably
  **before** the key becomes observable. The files contain the plaintext
  keys — the directory is as secret as the keys themselves. Every boot
  re-verifies each envelope's council signature; a corrupt file stops that
  purpose's scan at the last good epoch, and redelivering the epoch heals
  it.

Both are checked eagerly at startup: an unusable delivery directory or
malformed keyfile fails the boot before any socket binds.

## The delivery protocol

The council port (default `0.0.0.0:7876`) speaks length-prefixed CBOR — the
same framing as the custodian socket — with three methods: `Ping`,
`GetStatus`, and `DeliverEpochKey`. Envelope construction, the EIP-712
digest, and the message types live in `crates/council-delivery`, shared with
off-node council signer tooling.

The ceremony tool is `council-signer`
(`cargo build --release -p seismic-council-delivery --features cli`), with
`gen-key`, `status`, `typed-data`, and `deliver` subcommands covering the
whole rotation flow for both a locally held council key and an external
wallet.

One envelope carries one 32-byte purpose key for one `(purpose, epoch)`,
**signed with an ordinary Ethereum wallet**: the 65-byte `r || s || v`
signature is EIP-712 typed data (the crate's `typed_data_json` emits the
`eth_signTypedData_v4` JSON for MetaMask, `cast wallet sign --data`, or
hardware wallets), verified by recovering the signer and comparing it to
`--council-address`. The wallet signs the key's **keccak-256 commitment**,
never the key itself, so the secret doesn't pass through wallet UIs — while
the signature still binds the exact key bytes. The network id — derived
from `--chain-id` (`network_id_from_chain_id`, domain-separated SHA-256; no
manifest artifact needed in the centralized phase) — rides in the EIP-712
domain as `salt`, so a signature can never replay onto another chain.
Wallet approval screens show the fields: purpose, epoch, commitment.

Epochs are sequential per purpose: the first delivery is epoch 1 (epoch 0 is
forever derivation-sourced), and epoch N+1 is accepted only once N exists.
Sealing is deterministic (RFC 6979, no randomness), so re-sealing the same
payload reproduces the byte-identical envelope: redelivery is naturally
idempotent (`AlreadyDelivered`), and only a *different key* at an existing
epoch is an `EpochConflict`.

## Security posture

An open TCP port in the key-holding process is a deliberate, council-scoped
exception to the "no network listeners near keys" rule. Mitigations: the
64 KiB frame cap, a 16-connection cap, 30-second I/O timeouts, signature
verification before any state or disk write, and sanitized wire errors.
Transport-level authentication and confidentiality are the fronting
TLS/tunnel's job — authentication of *deliveries* is the per-envelope
council signature; `Ping`/`GetStatus` reveal only epoch counters.

The council must be an EOA — contract accounts (e.g. a Safe) sign via
EIP-1271, which cannot be verified off-chain by recovery. Rotating the
council key orphans persisted envelopes (they re-verify against the
currently configured `--council-address` on every boot); redeliver under the
new key to recover.

## Flags

| flag | env | default |
|---|---|---|
| `--socket` | — | `/run/seismic/custodian/custodian.sock` |
| `--root-key-file` | `SEISMIC_ROOT_KEY_FILE` | `/var/lib/seismic/custodian/root.key` (absent → pins the public shared default) |
| `--allow USER:PURPOSES` (repeatable) | — | deny-all |
| `--council-listen` | `SEISMIC_COUNCIL_LISTEN_ADDR` | `0.0.0.0:7876` |
| `--council-address` (required) | `SEISMIC_COUNCIL_ADDRESS` | — (`0x` + 20-byte Ethereum address hex) |
| `--chain-id` (required) | `SEISMIC_CHAIN_ID` | — (u64; council tooling must use the same value) |
| `--delivery-dir` | — | `/var/lib/seismic/custodian/deliveries` (contains plaintext keys; protect it) |

Like the TDX custodian, this binary links no async runtime; that guarantee
only holds when it is built in its own cargo invocation (see the
feature-unification note in `crates/custodian-ipc/Cargo.toml`).
