# Seismic enclave

The processes that run inside a Seismic node's TEE: they custody the network
root key, attest the node to peers and clients, and hand the node its runtime
configuration at boot.

## Layout

`bin/` holds the three deployed binaries; every crate under `crates/` is a
library they share.

### Binaries (`bin/`)

| Crate (dir) | Binary | Role |
|---|---|---|
| `tdx-init` | `tdx-init` | Boot-time init: receives node config over HTTP and writes the enclave/reth runtime env, then exits. |
| `attestation-service` | `seismic-attestation-service` | Network-facing JSON-RPC service (`:7878`): serves attestation evidence and purpose keys. Holds no key material — reaches the custodian over a Unix socket. |
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
| `measurement-admission` | Admission-ID derivation and measurement-policy compiler for the on-chain `MeasurementRegistry` (plus the policy-compiler CLI behind the `cli` feature). |
| `network-manifest` | Network-manifest schema (`NetworkManifestV1`) and `network_id` derivation. |
| `enclave-contract` | Rust interface to the enclave's on-chain contract. |

## Building

All crates build with `cargo build --workspace`. The custodian and attestation
service link Intel SGX/TDX libraries and only build on a Linux host with those
installed — see [tss-esapi-sys](https://crates.io/crates/tss-esapi-sys).

The custodian and attestation service run as a coordinated pair: the service
acquires the root key from the custodian over the socket at startup, so neither
runs standalone. `scripts/run_integration_tests.sh` exercises the real
topology (a custodian + service pair per node); the deployed systemd units live
in `seismic-images`.
