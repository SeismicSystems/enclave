# tdx-init

Small HTTP service that receives node configuration on every boot of a
Seismic TDX VM and translates it into per-service config files under
`/run/seismic/conf/` (tmpfs) for downstream services to consume.

Used by [seismic-images](https://github.com/SeismicSystems/seismic-images)
as part of the TDX VM boot sequence. The conf dir is on tmpfs and
recreated by `systemd-tmpfiles` at sysinit; deploy tooling re-POSTs the
config every boot.

## Usage

```
tdx-init wait-for-config
```

Behavior:

- Starts an HTTP server on port 8080 and waits for the operator to POST
  an `InitConfig` TOML. On receipt: validates the schema, writes
  per-service config files under `/run/seismic/conf/`, touches the
  sentinel `/run/seismic/conf/.tdx-init-done`, exits.
- The sentinel lives on tmpfs and is wiped on reboot, so the binary
  blocks for a fresh POST every boot. It still gates against multiple
  POSTs within a single boot (e.g. manual `systemctl restart`).

## InitConfig schema

The HTTP receiver accepts TOML with `Content-Type: application/toml`.
Unknown top-level sections or fields are rejected — see
[`src/config.rs`](src/config.rs).

```toml
[domain]
name = "<your.public.dns.name>"     # FQDN clients reach this VM at
email = "<contact@example.com>"     # ACME registration / renewal email

[enclave]                           # optional; defaults applied if absent
genesis_node = false                # true on exactly one VM per network
peers = ["http://10.0.0.1:7878"]    # required when genesis_node = false

[network]
manifest_base64 = "eyJib290c3RyYXBfbWVhc3VyZW1lbn..."
reth_genesis_base64 = "eyJjb25maWciOnsiY2hhaW5JZCI..."
```

`manifest_base64` carries the network's `network-manifest.json` as opaque
bytes (`network_id = SHA-256` of exactly those bytes). tdx-init validates
the manifest against the v1 schema at POST time — a bad manifest fails the
deploy with `400`, not a later boot — and writes the decoded bytes
verbatim to `network-manifest.json`, never parse-and-re-serialize. The
deploy tool's manifest-assembly step produces the value; the schema's
authoritative parser is the sibling
[`seismic-attestation`](../seismic-attestation) crate, kept in lockstep
with this crate via its shared fixture.

`reth_genesis_base64` carries the reth genesis JSON (chain spec) every
node's reth boots from. It is network-wide like the manifest, whose
`eth.genesis_hash` pins its genesis *block* (header and, via the state
root, the alloc) but not the file's `config` section (fork schedule) —
so POST-time validation is structural: valid JSON whose `config.chainId`
matches the manifest's `eth.chain_id`. The block-hash commitment is
enforced deploy-side and at ceremony time; see `src/reth_genesis.rs`.
Written verbatim to `reth-genesis.json`.

## Per-service outputs

After validation, tdx-init writes:

| File | Schema | Consumer |
|---|---|---|
| `/run/seismic/conf/domain.env` | `DOMAIN_NAME=...`, `DOMAIN_EMAIL=...` | `setup-nginx-ssl` (seismic-images) — `source`'d before invoking certbot for Let's Encrypt cert issuance and renewal |
| `/run/seismic/conf/enclave.env` | `SEISMIC_ENCLAVE_GENESIS_NODE=...`, `SEISMIC_ENCLAVE_PEERS=...` | `enclave.service` (seismic-images) — loaded via `EnvironmentFile=`, then consumed by [`seismic-enclave-server`](../enclave-server) through clap `env=` attributes |
| `/run/seismic/conf/network-manifest.json` | verbatim manifest bytes | [`seismic-enclave-server`](../enclave-server) — hashes the file itself to derive `network_id` for attestation bindings |
| `/run/seismic/conf/reth-genesis.json` | verbatim reth genesis bytes | `reth.service` (seismic-images) — passed to `seismic-reth node --chain` |

Each downstream service reads its own native format (env-var pairs,
either via systemd `EnvironmentFile=` or shell `source`); tdx-init is
the schema translator.

## Security

The HTTP listener on port 8080 is **unauthenticated and first-POST-wins**.
An attacker reaching :8080 ahead of the operator can post a malicious config.

Until the listener moves to a pull-based design (see TODO in `src/server.rs`):

- **Firewall ACL** restricting :8080 to the operator's /32, opened just
  before the deploy and closed after the POST returns. A `200 OK` confirms
  your config was accepted; `409 Conflict` or connection-refused means
  someone else won the race — tear down and redeploy.
