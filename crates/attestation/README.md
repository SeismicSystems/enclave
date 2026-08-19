# seismic-attestation

`seismic-attestation` is Seismic's application/policy layer on top of the
Flashbots `attestation` backend. The backend owns low-level quote generation and
verification; this crate owns Seismic-specific transcript semantics, network
identity, and typed verified outputs for Seismic services.

## Backend boundary

Seismic uses Flashbots `attestation` / `attested-tls` for near-term off-chain
Rust attestation flows. In particular, Seismic does **not** maintain its own
implementations of:

- Intel DCAP quote verification;
- PCCS collateral fetching / validation;
- TPM quote signature verification;
- Azure vTPM AK certificate-chain verification;
- Azure HCL / TDX quote binding verification.

Seismic code should call this crate's wrappers instead of depending on backend
internals directly.

## Seismic responsibilities

This crate is responsible for:

- re-exporting the `network-manifest.json` schema and
  `NetworkId = SHA-256(file bytes)` derivation from the dependency-light
  `seismic-network-manifest` crate, so node-side callers keep one import path;
- deriving domain-separated protocol bindings, including:
  - `tx_io_binding`,
  - `root_key_request_binding`,
  - `root_key_response_binding`,
  - `deploy_verification_binding`;
- generating local evidence for a caller-supplied binding;
- verifying remote evidence against an expected binding and a measurement policy;
- exposing Seismic-typed verified outputs so callers do not mix provider-specific
  measurements accidentally.

## Azure model

On Azure TDX CVMs, Seismic guest identity is based on Azure vTPM PCR
measurements. The raw TDX quote is still part of the evidence chain, but it
primarily attests the Azure/OpenHCL platform layers and binds the HCL report;
Seismic image admission should use PCR allowlisting through the Flashbots
measurement-policy format.

Measurement policy JSON is the backend format documented by Flashbots:

<https://github.com/flashbots/attested-tls/tree/main/crates/attestation#measurements-file>

Seismic-specific policy decisions that are outside the backend include which PCR
set is canonical for Seismic images, where accepted policies live
(deployment artifact, genesis storage, on-chain registry, or all of them), and
how policy updates are authorized.

## Evidence bindings

All Seismic evidence is bound to an explicit protocol digest. Callers should
construct the appropriate binding for the question being asked and pass that
binding into evidence generation / verification. Do not generate generic or
context-free evidence.

The binding helpers include `network_id` so evidence from one deployment cannot
be replayed on a clone network. The 32-byte binding digest is expanded to the
64-byte backend attestation input with `binding64_from_digest32`.

## Current APIs

Primary entry points:

```rust
use seismic_attestation::{generate_evidence, verify_evidence, SeismicMeasurementPolicy};
use seismic_attestation::bindings::{binding64_from_digest32, tx_io_binding};
```

- `generate_evidence(attestation_type, binding)` returns the backend
  `AttestationExchangeMessage`.
- `verify_evidence(evidence, expected_binding, policy)` verifies the backend
  evidence, enforces the measurement policy, and returns a typed
  `VerifiedSeismicAttestation`.
- `SeismicMeasurementPolicy::from_json_bytes` / `from_file` load the
  Flashbots-compatible policy artifact.

