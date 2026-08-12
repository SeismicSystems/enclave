# Integration Tests

`run_attestation_service_evidence_tdx_tests.sh` runs the live-TEE
attestation-service evidence suite on the self-hosted Azure TDX runner.
`run_attestation_service_admission_tdx_tests.sh` runs the service's
reth-backed responder-admission suite on the same runner.

## Covered flows

`test_two_node_root_key_bootstrap` starts two custodian + attestation-service
pairs over real custodian sockets and checks that the joining pair completes
the mutually attested wrapped-root-key bootstrap, with its custodian
installing the key and writing the LUKS keyfile handoff, and that both pairs
then serve the same purpose keys.

`test_tx_io_evidence_relying_party` runs the client side of the network's
tx-io key advertisement against a single genesis pair: a relying client
fetches `getTxIoAttestationEvidence`, independently derives the expected
network/key/epoch binding, and verifies the complete evidence envelope
through `seismic-attestation`; wrong bindings and malformed evidence are
rejected.

`test_four_node_root_key_distribution` starts one genesis pair plus three
joining pairs — two bootstrapping from the genesis node, one from an
already-bootstrapped joiner — and checks that every join completes and all
four custodians derive the same `tx_io_pk`.

The admission suite (`bin/attestation-service/tests/admission.rs`) covers the
responder's contract-backed bootstrap admission against real `seismic-reth`
dev nodes seeded with a measurement policy compiled at runtime from the
runner's own quoted PCRs: an accepted tuple authorizes exactly one root-key
wrap, an on-chain deprecation denies the next handshake without a service
restart, an unknown tuple is denied, and an unreachable or stale chain fails
closed. It additionally needs a `seismic-reth` binary (`SEISMIC_RETH_BIN`).

## Requirements

- An Azure TDX CVM with vTPM and IMDS access.
- Network access for attestation collateral/certificate retrieval.
- Root privileges for the TEE devices and `/run/seismic` runtime files.
- The image's resident node service stopped before the test takes over the
  TPM. On the CI image, the script asks Supervisor to stop it if present.
- A Rust toolchain.

Each script installs the checked-in network-manifest fixture under
`/run/seismic/conf`, builds its test binary as the runner user, and
executes it with `sudo`.

## Running

```bash
./scripts/run_attestation_service_evidence_tdx_tests.sh
./scripts/run_attestation_service_admission_tdx_tests.sh
```

CI runs the same scripts as the two steps of the
`attestation_service_tdx_tests` job in `.github/workflows/ci.yml` — one job,
so the suites share a single dependency build on the TDX runner.
