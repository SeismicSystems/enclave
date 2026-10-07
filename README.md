# Seismic enclave

The processes that run inside a Seismic node's TEE: they custody the network
root key, attest the node to peers and clients, and hand the node its runtime
configuration at boot.

## Layout

`bin/` holds the three deployed binaries; every crate under `crates/` is a
library they share, or one deploy's Rust CLI links.

### Binaries (`bin/`)

| Crate (dir) | Binary | Role |
|---|---|---|
| `tdx-init` | `tdx-init` | Boot-time init: receives node config over HTTP and writes the enclave/reth runtime env, then exits. |
| `attestation-service` | `seismic-attestation-service` | Network-facing JSON-RPC service (`:7878`): serves attestation evidence and purpose keys, and from boot the founding harvest over HTTP (`:7879`): summit's pubkeys and the custodian's candidate `tx_io_pk@0`, and a quote over them until the manifest exists. The node's only TPM user. Holds no key material — reaches the custodian over a Unix socket. |
| `custodian-service` | `seismic-custodian-service` | Standalone service for the RAM-only root-key custodian: no network listener, minimal Unix-socket API, owns the per-boot LUKS keyfile handoff. |

### Libraries (`crates/`)

| Crate | What it is |
|---|---|
| `enclave` | Shared enclave API types (JSON-RPC surface); imported by seismic-reth. |
| `crypto` | AES-GCM / ECDH / HKDF helpers shared across the Seismic stack. |
| `custodian` | RAM-only custodian of the network root key. |
| `custodian-ipc` | Wire protocol, client, and server for the custodian Unix socket (plus a debug CLI behind the `cli` feature). |
| `attestation` | Attestation evidence types and policy checks. |
| `attestation-rpc` | Purpose-specific attestation JSON-RPC types. |
| `measurement-admission` | Admission-ID derivation and measurement-policy compiler for the on-chain `MeasurementRegistry`; deploy's Rust CLI links it to promote measurements and compile the policy. |
| `network-manifest` | Network-manifest schema (`NetworkManifestV1`) and `network_id` derivation. |
| `manifest` | Not used on nodes: the manifest's sole emitter (`seismic-manifest`) — `render` turns a `NetworkManifestV1` into the canonical `network-manifest.json` bytes. Kept apart from the parse-only schema crate so no node build can re-serialize the file. Deploy's Rust CLI links it. |
| `verify-quote` | Not used on nodes: relying-party verification of node quotes against a measurement policy (`seismic-verify-quote`). One verification path, two evidence sources: `verify_harvest` checks a founding node's summit-keys quote live and hands back the founding archive that `verify_archived_harvest` replays offline later, `verify_deploy` challenges a freshly provisioned node's `getDeployVerificationEvidence` RPC itself. Deploy's Rust CLI links it; its `verify harvest` / `verify deploy` commands are these two functions. |
| `measurement-registry-client` | Read-only Alloy client for the on-chain `MeasurementRegistry`. |
| `tdx-init-config` | Schema of the bootstrap config `tdx-init` accepts over HTTP: both ends of that POST link it, so deploy tooling builds the struct the node deserializes. |

## Boot chain

How these binaries and the image's units relate across one node boot is
[the node lifecycle](https://github.com/SeismicSystems/seismic/blob/main/docs/tee/architecture.md#node-lifecycle-power-on-to-serving);
the founding harvest, its one founding-specific step, is
[network founding](https://github.com/SeismicSystems/seismic/blob/main/docs/tee/network-founding.md).
Unit ordering and the setup scripts live in seismic-images; deploy drives
the node from off-box.

## Building

All crates build with `cargo build --workspace`. The custodian and attestation
service link Intel SGX/TDX libraries and only build on a Linux host with those
installed — see [tss-esapi-sys](https://crates.io/crates/tss-esapi-sys).

The custodian and attestation service run as a coordinated pair: the service
acquires the root key from the custodian over the socket at startup, so neither
runs standalone. `scripts/run_integration_tests.sh` exercises the real
topology (a custodian + service pair per node); the deployed systemd units live
in `seismic-images`.
