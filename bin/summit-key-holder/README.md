# summit-key-holder

Pre-manifest holder of a node's summit consensus keys. The network
manifest pins every founding validator's pubkeys, so the keys must
exist before the manifest does — before the config POST, before
admission, before LUKS. This service generates the
summit keypairs (ed25519 node identity + BLS12-381 MinPk consensus) in
RAM at boot, serves `{pubkeys, quote}` over HTTP for deploy's founding
harvest, and persists them into summit's keystore once LUKS has opened
`/persistent`. Design:
[network-founding.md](https://github.com/SeismicSystems/seismic/blob/main/docs/tee/network-founding.md).

## Usage

```sh
# The long-running service (summit-key-holder.service, User=summit):
summit-key-holder serve \
    [--listen 0.0.0.0:7879] \
    [--keystore-dir /persistent/summit/keys] \
    [--control-socket /run/summit-key-holder/control.sock] \
    [--network-manifest /run/seismic/conf/network-manifest.json]

# summit.service's ExecStartPre — blocks until the keystore is written
# (first boot) or confirmed (reboot):
summit-key-holder persist-wait [--control-socket ...]
```

## HTTP API (`:7879`, plain HTTP)

| Endpoint | Response |
|---|---|
| `GET /v1/keys` | `{node_public_key, consensus_public_key}` — bare lowercase hex (64 / 96 chars), exactly as summit renders them. Served for life; post-persist it reads the keystore and feeds deploy's launch-time continuity assertion. |
| `GET /v1/quote?nonce=<64-hex>` | The keys plus `evidence`, a JSON-serialized `AttestationExchangeMessage` with `report_data = founding_summit_keys_binding(nonce, node_pk, consensus_pk)` — the exact bytes `verify-quote --evidence` consumes and deploy's harvest archives verbatim. `410 Gone` once the network manifest exists. |

Quote generation opens the raw TPM (`/dev/tpm0`, exclusive) and costs
seconds per call; requests are serialized in-process. Once the manifest
lands, attestation-service owns the TPM quote path and this service
refuses to quote — per boot, not permanently: the conf dir is tmpfs, so
the window reopens on every boot until the config re-POST. That is why
the port's NSG restriction to `operator_ip_cidr` is permanent.

## Persist flow

`persist` is one operation on the Unix control socket (never the
network listener): write the keystore if absent, confirm it decodes if
present, discard the RAM keys either way. A half-written keystore is
finished on retry only if its one existing file provably holds this
boot's own RAM key (an interrupted persist — each file lands
atomically); any other partial keystore is refused, since overwriting
it would silently mint keys the manifest never pinned. The retry path
matters because production images have no shell: rebooting a founder
burns its pinned keys, so a transient write failure that couldn't heal
through systemd's restart of summit.service would force a full
re-found. `persist-wait` retries while
the holder is unreachable and exits nonzero on a definitive failure, so
summit's start fails loudly rather than coming up without its pinned
keys.

The keystore is summit's wire format byte-for-byte (`node_key.pem` /
`consensus_key.pem`, hex of the commonware-codec encoding, 0600 in a
0700 dir), pinned by a golden-vector test against a keystore summit's
own `keys generate` emitted. The commonware dependency is pinned `=` to
summit's exact version for the same reason.

## Security

- The HTTP listener is up at the most exposed moment of the node's life
  (pre-manifest, pre-admission). It holds the private keys in-process —
  the accepted v1 trade; the control socket is the boundary along which
  a custody split would happen — but never serves them: only pubkeys
  and quotes leave the process.
- A harvested key is trustworthy only if the same box later accepts the
  real configure cleanly; any anomaly burns the whole harvest
  (deploy-side procedure, nothing here enforces it).
- RAM keys that never persist die with the process; both commonware
  private-key types zeroize on drop. A reboot inside the founding
  window therefore produces fresh keys — the launch-time continuity
  assertion, not this service, is what catches the resulting pin
  mismatch.
