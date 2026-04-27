# tdx-init

Small HTTP service that receives node configuration on first boot of a
Seismic TDX VM and writes it to `/persistent/conf/node.json` for
downstream services to consume (currently
[`setup-nginx-ssl`](https://github.com/SeismicSystems/seismic-images/blob/seismic/modules/seismic/mkosi.extra/usr/bin/setup-nginx-ssl),
which reads the domain and email for Let's Encrypt cert issuance).

Used by [seismic-images](https://github.com/SeismicSystems/seismic-images)
as part of the TDX VM boot sequence. Runs after
`persistent-luks-setup.service` has provisioned and mounted `/persistent`,
before `nginx-ssl-setup.service` consumes the config.

## Usage

```
tdx-init wait-for-config
```

Behavior:

- **Subsequent boots**: if `/persistent/conf/node.json` already exists,
  exits immediately.
- **First boot**: starts an HTTP server on port 8080 and waits for the
  operator to POST an `InitConfig` JSON. On receipt: writes the config
  to `/persistent/conf/node.json` (plus, transitionally, any SSH keys to
  `authorized_keys` — see "transitional fields" below), exits.

The expected payload after follow-up cleanups land is:

```json
{
  "domain": {
    "name": "<your.public.dns.name>",
    "email": "<contact@example.com>"
  }
}
```

### Transitional fields

The current `InitConfig` schema also accepts `ssh_keys`, `args`, and
`log` fields, all inherited from the prior version of this fork. They
are slated for removal in follow-up commits:

- `ssh_keys` — written to `/home/searcher/.ssh/authorized_keys`. The
  seismic image has no `openssh-server` package and no `searcher`
  user, so these keys are inert. Removal in next commit.
- `args.{reth, summit, enclave}` and `log.{reth, summit, enclave}` —
  no longer read by anything since the seismic-images service unit
  files were inlined. Removal in commit after.
