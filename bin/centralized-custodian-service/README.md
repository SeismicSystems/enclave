# seismic-centralized-custodian-service

The custodian variant for centrally operated networks: purpose keys at epochs
`>= 1` are not derived from the root key — they arrive as **signed, encrypted
deliveries from a security council** over a TCP port, and the Unix socket
serves exactly what has been delivered. Asking for an epoch the council has
not delivered yet answers the typed `EpochKeyUnavailable` error instead of
deriving, which makes the council the network's actual rotation authority.

Everything else matches `seismic-custodian-service` byte-for-byte: epoch-0
derivations, the root-key bootstrap trio, the LUKS keyfile handoff, and the
`--allow USER:PURPOSES` socket ACL (those modules are linked from that crate
as a library).

## The delivery protocol

The council port (default `0.0.0.0:7879`) speaks length-prefixed CBOR — the
same framing as the custodian socket — with three methods: `Ping`,
`GetStatus`, and `DeliverEpochKey`. Envelope construction, binding digests,
and the message types live in `crates/council-delivery`, shared with off-node
signer tooling.

One envelope carries one 32-byte purpose key for one `(purpose, epoch)`:

- **encrypted** to the custodian's *inbox keypair* (ECDH + AES-256-GCM, the
  context digest as AAD). The inbox key is derived from the network-wide root
  key at the fixed `council-inbox` purpose, so every node shares it: the
  council seals once and sends the same envelope to every node. `GetStatus`
  publishes the inbox pubkey.
- **signed** by the council secp256k1 key (`--council-pubkey`) over a
  domain-separated digest of the complete payload *including the ciphertext*,
  so a valid signature cannot be re-attached to different key bytes, another
  network, purpose, epoch, or recipient.

Epochs are sequential per purpose: the first delivery is epoch 1 (epoch 0 is
forever derivation-sourced), and epoch N+1 is accepted only once N exists.
Byte-identical redelivery is idempotent (`AlreadyDelivered`); anything else
at an existing epoch is an `EpochConflict` — council tooling must persist and
re-send its **original** envelopes when retrying, since a re-encryption of
the same key is a different envelope by construction.

## Persistence and boot ordering

Accepted envelopes persist verbatim (signed + encrypted, never plaintext) to
`--delivery-dir` as `<purpose>/<epoch>.cbor`, written durably **before** the
key becomes observable. On boot every file is re-verified and re-decrypted; a
corrupt or tampered file stops that purpose's scan at the last good epoch and
a redelivery of the damaged epoch heals it.

The delivery dir defaults to `/persistent/...`, which is unlocked by this
process's own LUKS keyfile handoff — so the store is unreachable at process
start by construction. Loading is therefore lazy: until the root key is
present and the directory is creatable, deliveries are refused with a
retriable rejection (`RootKeyAbsent` / `PersistenceUnavailable`),
`GetStatus` still answers (with `accepting_deliveries: false`), and delivered
epochs answer `EpochKeyUnavailable` on the Unix socket.

## Security posture

An open TCP port in the key-holding process is a deliberate, council-scoped
exception to the "no network listeners near keys" rule. Mitigations: the
64 KiB frame cap, a 16-connection cap, 30-second I/O timeouts, signature
verification before any state or disk write, and sanitized wire errors.
Transport-level authentication is intentionally absent — authentication is
the per-envelope council signature; `Ping`/`GetStatus` reveal only public
data. **The image's firewall must confine who can reach the port.**

Rotating the council key orphans persisted envelopes (they re-verify against
the currently configured `--council-pubkey` on every boot); redeliver under
the new key to recover.

## Flags

| flag | env | default |
|---|---|---|
| `--socket` | — | `/run/seismic/custodian/custodian.sock` |
| `--genesis-node` | `SEISMIC_CUSTODIAN_GENESIS_NODE` | `false` |
| `--luks-keyfile` | — | `/run/seismic/custodian/luks-keys` |
| `--allow USER:PURPOSES` (repeatable) | — | deny-all |
| `--council-listen` | `SEISMIC_COUNCIL_LISTEN_ADDR` | `0.0.0.0:7879` |
| `--council-pubkey` (required) | `SEISMIC_COUNCIL_PUBKEY` | — (`0x` + 33-byte compressed SEC1 hex) |
| `--network-manifest` | — | `/run/seismic/conf/network-manifest.json` |
| `--delivery-dir` | — | `/persistent/seismic/custodian/deliveries` |

## Deployment follow-ups (out of this repo)

- systemd unit + service user, the tmpfiles socket dir, and the delivery-dir
  ownership live in **seismic-images**, as does the firewall rule for the
  council port.
- If the council pubkey should flow from the operator's `node.toml`,
  `bin/tdx-init` needs a `write_centralized_custodian_env` emitting
  `SEISMIC_COUNCIL_PUBKEY` (and optionally the listen address).

Like the standalone custodian, this binary links no async runtime; that
guarantee only holds when it is built in its own cargo invocation (see the
feature-unification note in `crates/custodian-ipc/Cargo.toml`).
