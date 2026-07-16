# Integration Tests

`run_integration_tests.sh` runs the live-TEE attestation-service integration
test on the self-hosted Azure TDX runner.

## Covered flow

`test_get_wrapped_root_key_bootstrap` starts two key-custodian +
attestation-service pairs over real custodian sockets and checks that:

1. the joining pair completes the mutually attested wrapped-root-key
   bootstrap, with its custodian installing the key and writing the LUKS
   keyfile handoff;
2. both pairs derive the same purpose keys;
3. a relying client fetches `getTxIoAttestationEvidence`, independently derives
   the expected network/key/epoch binding, and verifies the complete evidence
   envelope through `seismic-attestation`;
4. wrong bindings and malformed evidence are rejected.

TODO: add contract-backed bootstrap-admission coverage as a distinct
reth-backed integration test with PCR policy seeded in genesis.

## Requirements

- An Azure TDX CVM with vTPM and IMDS access.
- Network access for attestation collateral/certificate retrieval.
- Root privileges for the TEE devices and `/run/seismic` runtime files.
- The image's resident node service stopped before the test takes over the
  TPM. On the CI image, the script asks Supervisor to stop it if present.
- A Rust toolchain.

The script installs the checked-in network-manifest fixture under
`/run/seismic/conf`, builds the integration-test binary as the runner user, and
executes it with `sudo`.

## Running

```bash
./scripts/run_integration_tests.sh
```

CI runs the same script in the `integration_tests` job in
`.github/workflows/ci.yml`.
