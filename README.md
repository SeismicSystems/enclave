# Seismic enclave

The processes that run inside a Seismic node's TEE: they custody the network
root key, attest the node to peers and clients, and hand the node its runtime
configuration at boot.

## Layout

`bin/` holds the three deployed binaries plus `verify-quote`, which runs
off-node in deploy's hands; every crate under `crates/` is a library they
share.

### Binaries (`bin/`)

| Crate (dir) | Binary | Role |
|---|---|---|
| `tdx-init` | `tdx-init` | Boot-time init: receives node config over HTTP and writes the enclave/reth runtime env, then exits. |
| `attestation-service` | `seismic-attestation-service` | Network-facing JSON-RPC service (`:7878`): serves attestation evidence and purpose keys. Holds no key material — reaches the custodian over a Unix socket. |
| `custodian-service` | `seismic-custodian-service` | Standalone service for the RAM-only root-key custodian: no network listener, minimal Unix-socket API, owns the per-boot LUKS keyfile handoff. |
| `centralized-custodian-service` | `seismic-centralized-custodian-service` | Standalone custodian for the network's centralized phase (runs without the other services): epochs >= 1 are Ethereum-wallet-signed security-council deliveries over a TCP port (`:7876`, fronted by the deployment's TLS/tunnel) instead of root-key derivations; same Unix-socket API otherwise, root key persisted in a local keyfile. |
| `verify-quote` | `verify-quote` | Not deployed to nodes: verification-only CLI that DCAP-verifies one founding node's summit-keys harvest quote against a measurement policy (JSON on stdout, exit 0 ⇔ verified). Shelled out to by deploy's harvest step. |

### Libraries (`crates/`)

| Crate | What it is |
|---|---|
| `enclave` | Shared enclave API types (JSON-RPC surface); imported by seismic-reth. |
| `crypto` | AES-GCM / ECDH / HKDF helpers shared across the Seismic stack. |
| `custodian` | RAM-only custodian of the network root key. |
| `custodian-ipc` | Wire protocol, client, and server for the custodian Unix socket (plus a debug CLI behind the `cli` feature). |
| `council-delivery` | Wire types, binding digests, and envelope crypto for security-council epoch-key deliveries; shared with off-node council signer tooling. |
| `attestation` | Attestation evidence types and policy checks. |
| `attestation-rpc` | Purpose-specific attestation JSON-RPC types. |
| `measurement-admission` | Admission-ID derivation and measurement-policy compiler for the on-chain `MeasurementRegistry` (plus the policy-compiler CLI behind the `cli` feature). |
| `network-manifest` | Network-manifest schema (`NetworkManifestV1`) and `network_id` derivation. |
| `measurement-registry-client` | Read-only Alloy client for the on-chain `MeasurementRegistry`. |

## Building

All crates build with `cargo build --workspace`. The custodian and attestation
service link Intel SGX/TDX libraries and only build on a Linux host with those
installed — see [tss-esapi-sys](https://crates.io/crates/tss-esapi-sys).

The custodian and attestation service run as a coordinated pair: the service
acquires the root key from the custodian over the socket at startup, so neither
runs standalone. `scripts/run_integration_tests.sh` exercises the real
topology (a custodian + service pair per node); the deployed systemd units live
in `seismic-images`.
