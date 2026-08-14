# seismic-centralized-custodian-service

The custodian for the network's **centralized phase**, before custody moves
to decentralized TEEs. It runs standalone — no attestation service, no
tdx-init, no setup-persistent-luks — and serves the same Unix-socket API as
`seismic-custodian-service`, with one difference: purpose keys at epochs
`>= 1` are not derived from the root key. They arrive as **signed, encrypted
deliveries from a security council** over a TCP port, and asking for an
epoch the council has not delivered answers the typed `EpochKeyUnavailable`
error instead of deriving — making the council the network's actual rotation
authority.

Epoch-0 derivations use the same HKDF paths as the TDX custodian, so
consumers see identical bytes when the network later migrates. The root-key
bootstrap methods answer a stable error: there is no attested bootstrap
here.

## State on disk

Two things persist, both under `/var/lib/seismic/custodian/` by default:

- **The root keyfile** (`--root-key-file`, 32 raw bytes, mode 0600):
  generated from the OS CSPRNG on first boot, loaded on every boot after.
  Epoch-0 keys and the council inbox key derive from it, so back it up —
  losing it changes every derived key and orphans all persisted deliveries.
- **Delivery envelopes** (`--delivery-dir`, `<purpose>/<epoch>.cbor`):
  accepted deliveries stored verbatim — signed and encrypted, never
  plaintext — written durably **before** the key becomes observable. Every
  boot re-verifies and re-decrypts them; a corrupt file stops that purpose's
  scan at the last good epoch, and redelivering the damaged epoch heals it.

Both are checked eagerly at startup: an unusable delivery directory or
malformed keyfile fails the boot before any socket binds.

## The delivery protocol

The council port (default `0.0.0.0:7876`) speaks length-prefixed CBOR — the
same framing as the custodian socket — with three methods: `Ping`,
`GetStatus`, and `DeliverEpochKey`. Envelope construction, binding digests,
and the message types live in `crates/council-delivery`, shared with
off-node signer tooling.

One envelope carries one 32-byte purpose key for one `(purpose, epoch)`:

- **encrypted** to the custodian's *inbox keypair* (ECDH + AES-256-GCM, the
  context digest as AAD). The inbox key derives from the root key at the
  fixed `council-inbox` purpose; `GetStatus` publishes its public half for
  the council to seal against.
- **signed with an ordinary Ethereum wallet**: the 65-byte `r || s || v`
  signature is EIP-712 typed data (`crates/council-delivery`'s `eip712`
  module emits the `eth_signTypedData_v4` JSON for MetaMask,
  `cast wallet sign --data`, or hardware wallets), verified by recovering
  the signer and comparing it to `--council-address`. The network id —
  derived from `--chain-id` (`network_id_from_chain_id`, domain-separated
  SHA-256; no manifest artifact needed in the centralized phase) — rides in
  the EIP-712 domain as `salt`, and the ciphertext is a signed field, so a
  valid signature cannot be re-attached to different key bytes, another
  chain, purpose, epoch, or recipient. Wallet approval screens show the
  actual fields: purpose, epoch, recipient inbox key.

Council tooling therefore splits in two: encryption (the ECIES seal) runs in
the tool, authorization is a wallet signature over the typed data — or, for
a script-driven council holding a raw key, `seal_delivery` does both in one
call and produces byte-identical signatures.

Epochs are sequential per purpose: the first delivery is epoch 1 (epoch 0 is
forever derivation-sourced), and epoch N+1 is accepted only once N exists.
Byte-identical redelivery is idempotent (`AlreadyDelivered`); anything else
at an existing epoch is an `EpochConflict` — council tooling must persist
and re-send its **original** envelopes when retrying, since a re-encryption
of the same key is a different envelope by construction.

## Security posture

An open TCP port in the key-holding process is a deliberate, council-scoped
exception to the "no network listeners near keys" rule. Mitigations: the
64 KiB frame cap, a 16-connection cap, 30-second I/O timeouts, signature
verification before any state or disk write, and sanitized wire errors.
Transport-level authentication is intentionally absent — authentication is
the per-envelope council signature; `Ping`/`GetStatus` reveal only public
data. **The deployment's firewall must confine who can reach the port.**

Rotating the council key orphans persisted envelopes (they re-verify against
the currently configured `--council-address` on every boot); redeliver under
the new key to recover. The council must be an EOA — contract accounts
(e.g. a Safe) sign via EIP-1271, which cannot be verified off-chain by
recovery.

## Flags

| flag | env | default |
|---|---|---|
| `--socket` | — | `/run/seismic/custodian/custodian.sock` |
| `--root-key-file` | `SEISMIC_ROOT_KEY_FILE` | `/var/lib/seismic/custodian/root.key` |
| `--allow USER:PURPOSES` (repeatable) | — | deny-all |
| `--council-listen` | `SEISMIC_COUNCIL_LISTEN_ADDR` | `0.0.0.0:7876` |
| `--council-address` (required) | `SEISMIC_COUNCIL_ADDRESS` | — (`0x` + 20-byte Ethereum address hex) |
| `--chain-id` (required) | `SEISMIC_CHAIN_ID` | — (u64; council tooling must use the same value) |
| `--delivery-dir` | — | `/var/lib/seismic/custodian/deliveries` |

Like the TDX custodian, this binary links no async runtime; that guarantee
only holds when it is built in its own cargo invocation (see the
feature-unification note in `crates/custodian-ipc/Cargo.toml`).
