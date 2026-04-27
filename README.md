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
  to `/persistent/conf/node.json`, exits.

The expected payload after follow-up cleanup lands is:

```json
{
  "domain": {
    "name": "<your.public.dns.name>",
    "email": "<contact@example.com>"
  }
}
```

### Transitional fields

The current `InitConfig` schema also accepts `args` and `log` fields,
inherited from the prior version of this fork. They are no longer
read by anything since seismic-images inlined service args directly
into the systemd unit files; removal in the next commit.
