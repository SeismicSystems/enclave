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
[network]                            # coordinator-produced; a function of the network, not of this node
manifest_base64 = "eyJib290c3RyYXBfbWVhc3VyZW1lbn..."
reth_genesis_base64 = "eyJjb25maWciOnsiY2hhaW5JZCI..."
summit_genesis_base64 = "bmFtZXNwYWNlID0gInNlaXNtaWM..."
bootnodes = ["enode://<128 hex pubkey>@host:port"]  # the cohort's peers; [] only on the genesis node

[node]                               # this node only
external_ip = "203.0.113.7"          # this VM's public IP (reth --nat extip:)
genesis_node = false                 # optional (default false); true on exactly one VM per network

[node.domain]
name = "<your.public.dns.name>"      # FQDN clients reach this VM at
email = "<contact@example.com>"      # ACME registration / renewal email
```

`manifest_base64` carries the network's `network-manifest.json` as opaque
bytes (`network_id = SHA-256` of exactly those bytes). tdx-init validates
the manifest against the v1 schema at POST time — a bad manifest fails the
deploy with `400`, not a later boot — and writes the decoded bytes
verbatim to `network-manifest.json`, never parse-and-re-serialize. The
deploy tool's manifest-assembly step produces the value; the schema's
authoritative parser is the sibling
[`seismic-attestation`](../../crates/attestation) crate, kept in lockstep
with this crate via its shared fixture. It is also the document that pins the
other two `[network]` artifacts — `eth.genesis_hash` commits to
`reth_genesis_base64`'s bytes and `summit.genesis_config_digest` to
`summit_genesis_base64`'s — so the three are one assembled set: pairing a
manifest with a genesis it doesn't pin produces a node that can't join the
cohort it claims to belong to.

`reth_genesis_base64` carries the reth genesis JSON (chain spec) every
node's reth boots from. It is network-wide like the manifest, whose
`eth.genesis_hash` pins its genesis *block* (header and, via the state
root, the alloc) but not the file's `config` section (fork schedule) —
so POST-time validation is structural: valid JSON whose `config.chainId`
matches the manifest's `eth.chain_id`. The block-hash commitment is
enforced deploy-side and at ceremony time; see `src/reth_genesis.rs`.
Written verbatim to `reth-genesis.json`.

`summit_genesis_base64` carries the summit genesis TOML — the consensus-layer
genesis every node's summit boots from. It is complete at delivery (the
founding ceremony harvests the validator set into it before the POST), and the
manifest's `summit.genesis_config_digest` pins it: summit's own SHA-256 over a
domain-prefixed SSZ serialization of the genesis, covering the consensus
parameters and every validator's node/consensus pubkeys and withdrawal
credentials, but not `ip_address`. tdx-init cannot recompute that digest
without reimplementing summit's SSZ layout, and doesn't need to — deploy
verifies it against the manifest pin before POSTing, and summit derives its
P2P and signing domains from `chain_domain(config_digest)`, so a node fed a
divergent genesis can't complete a handshake. POST-time validation is
therefore structural, like the reth half: valid TOML whose `namespace` matches
the manifest's `summit.namespace` (`src/summit_genesis.rs`). Written verbatim
to `summit-genesis.toml`.

`[network].bootnodes` is the network-wide devp2p bootnode list — the single
source for the cohort's peer machines. Dropping this node's own entry leaves
the peer enodes, which three consumers read in two renderings:

- **reth's `--bootnodes`** (rendered into `reth-p2p.env`, see below) seeds
  discv5, where one live bootnode is enough for the DHT to flood the rest.
  Bootstrap is one-shot per boot.
- **reth's `--trusted-peers`** takes the same enodes. reth dials these directly
  over RLPx with retry, so a lost discv5 round-trip costs latency instead of a
  seat in the tx-gossip mesh.
- **the attestation service's root-key fetch list** (`attestation.env`) takes
  the same machines as `http://<host>:7878`.

Rendering the lists instead of delivering three makes skew between them
unrepresentable — all three name the same machines by construction.

`[node].external_ip` is this VM's public IP — Azure NICs hold private
addresses, so reth's NAT autodetection can't be trusted; it is also what
identifies the node's own enode in the bootnode set. Both fields are
validated structurally at POST time (`src/peers.rs`): each bootnode must be
`enode://<128 hex pubkey>@host:port`, `external_ip` must parse as an IP address, and
a node with `genesis_node = false` must end up with at least one root-key
peer; a bad value fails the deploy with `400`. `bootnodes = []` is valid only
on the genesis node (nothing to dial; it mints `root_key` itself).

## Per-service outputs

After validation, tdx-init writes:

| File | Schema | Consumer |
|---|---|---|
| `/run/seismic/conf/domain.env` | `DOMAIN_NAME=...`, `DOMAIN_EMAIL=...` | `setup-nginx-ssl` (seismic-images) — `source`'d before invoking certbot for Let's Encrypt cert issuance and renewal |
| `/run/seismic/conf/custodian.env` | `SEISMIC_CUSTODIAN_GENESIS_NODE=...` | `custodian.service` (seismic-images) — loaded via `EnvironmentFile=`; [`seismic-custodian-service`](../custodian-service) reads the genesis flag through clap `env=` |
| `/run/seismic/conf/attestation.env` | `SEISMIC_ROOT_KEY_PEERS=...` | `attestation.service` (seismic-images) — loaded via `EnvironmentFile=`; [`seismic-attestation-service`](../attestation-service) reads the peer list through clap `env=`. Derived from `[network].bootnodes`, not a config field |
| `/run/seismic/conf/network-manifest.json` | verbatim manifest bytes | [`seismic-attestation-service`](../attestation-service) — hashes the file itself to derive `network_id` for attestation bindings |
| `/run/seismic/conf/reth-genesis.json` | verbatim reth genesis bytes | `reth.service` (seismic-images) — passed to `seismic-reth node --chain` |
| `/run/seismic/conf/summit-genesis.toml` | verbatim summit genesis bytes | `summit.service` (seismic-images) — passed to `summit --genesis-path` |
| `/run/seismic/conf/reth-p2p.env` | `RETH_BOOTNODES_FLAG=...`, `RETH_TRUSTED_PEERS_FLAG=...`, `RETH_NAT_FLAG=...` | `reth.service` (seismic-images) — loaded via `EnvironmentFile=`; each var holds a whole flag (`--bootnodes <csv>` / `--trusted-peers <csv>` / `--nat extip:<ip>`) or is empty, and the unit places the unquoted `$RETH_*_FLAG` vars on the command line so empty ones drop out |

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
