# tdx-init

Small HTTP service that receives node configuration on first boot of a
Seismic TDX VM and translates it into per-service config files under
`/persistent/conf/` for downstream services to consume.

Used by [seismic-images](https://github.com/SeismicSystems/seismic-images)
as part of the TDX VM boot sequence. Runs after
`persistent-luks-setup.service` has provisioned and mounted
`/persistent`, before any node services start.

## Usage

```
tdx-init wait-for-config
```

Behavior:

- **First boot**: starts an HTTP server on port 8080 and waits for the
  operator to POST an `InitConfig` TOML. On receipt: validates the
  schema, writes per-service config files under `/persistent/conf/`,
  touches the sentinel `/persistent/conf/.tdx-init-done`, exits.
- **Subsequent boots**: if the sentinel exists, exits immediately
  (config has already been delivered).

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
```

## Per-service outputs

After validation, tdx-init writes:

| File | Schema | Consumer |
|---|---|---|
| `/persistent/conf/domain.env` | `DOMAIN_NAME=...`, `DOMAIN_EMAIL=...` | `setup-nginx-ssl` (seismic-images) — `source`'d before invoking certbot for Let's Encrypt cert issuance and renewal |
| `/persistent/conf/enclave.env` | `SEISMIC_ENCLAVE_GENESIS_NODE=...`, `SEISMIC_ENCLAVE_PEERS=...` | `enclave.service` (seismic-images) — loaded via `EnvironmentFile=`, then consumed by `seismic-enclave-server` through clap `env=` attributes |

Each downstream service reads its own native format (env-var pairs,
either via systemd `EnvironmentFile=` or shell `source`); tdx-init is
the schema translator.

## Security

The HTTP listener on port 8080 is **unauthenticated and
first-POST-wins**. An attacker who reaches that port ahead of the
operator can write malicious config — most damagingly, attacker-
controlled enclave peers, which causes the enclave to fetch `root_key`
from an attacker-controlled endpoint at startup (the
`boot_share_root_key` flow doesn't verify the responder's TDX quote).
Today the only defense is cloud-firewall ACLs restricting :8080 to the
operator's IP. Tracked as a TODO in `src/server.rs` with three fix
candidates (RA-TLS on the listener, cloud-metadata-pull instead of an
inbound port, or signed payloads with an image-baked verifier
pubkey).
