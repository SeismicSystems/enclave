# Integration Tests

The `evidence` target runs the live-TEE attestation-service evidence suite on
the self-hosted Azure TDX runner. The `admission` target runs the service's
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

`test_deploy_verification_relying_party` runs an operator's deploy
verification against a single genesis pair: the verifier sends a fresh
`deployment_nonce`
to `getDeployVerificationEvidence`, independently derives the expected
network/nonce binding, and verifies the complete evidence envelope; bindings
for another nonce or another network are rejected.

`test_four_node_root_key_distribution` starts one minting pair plus three
joining pairs — two bootstrapping from the minting pair, one from an
already-bootstrapped joiner — and checks that every join completes and all
four custodians derive the same `tx_io_pk`.

The admission suite (`bin/attestation-service/tests/admission.rs`) covers the
responder's contract-backed bootstrap admission against real `seismic-reth`
dev nodes seeded with a measurement policy compiled at runtime from the
runner's own quoted PCRs: an accepted tuple authorizes exactly one root-key
wrap, an on-chain deprecation denies the next handshake without a service
restart, an unknown tuple is denied, and an unreachable chain, a stale chain,
or a chain the manifest does not commit to fails closed. It additionally needs
a `seismic-reth` binary (`SEISMIC_RETH_BIN`).

## Requirements

- An Azure TDX CVM with vTPM and IMDS access.
- Network access for attestation collateral/certificate retrieval.
- Read-write access to the raw TPM device (`/dev/tpm0`), which quote
  generation opens. Ubuntu's udev rules give it to group `root` (only
  `/dev/tpmrm0` goes to `tss`), so either run as root or reassign it and join
  `tss`:

  ```bash
  echo 'KERNEL=="tpm0", GROUP="tss", MODE="0660"' | sudo tee /etc/udev/rules.d/70-tpm0-tss.rules
  sudo udevadm control --reload && sudo udevadm trigger /dev/tpm0
  sudo usermod -aG tss "$USER"   # then log in again
  ```

- No other process holding the TPM: the kernel hands `/dev/tpm0` to one
  process at a time. Stop any resident node service first.
- A Rust toolchain.

Every node under test gets its own conf dir (`--conf-dir`), written the way
tdx-init writes a node's: the network manifest, the root-key peers, and the
done marker. The evidence suite uses the checked-in network-manifest fixture;
the admission tests render their own, because a network's identity commits to
its genesis hash and each of those tests mints a fresh genesis.

## Running

```bash
cargo test -p seismic-attestation-service --test evidence
SEISMIC_RETH_BIN=/path/to/seismic-reth cargo test -p seismic-attestation-service --test admission
```

The admission tests find `seismic-reth` through `SEISMIC_RETH_BIN`, then
`PATH`, then a sibling `seismic-reth` checkout's `target/{debug,release}`.
Each test panics up front if it cannot open `/dev/tpm0`.

Use `cargo test`, not nextest. Each target is one binary whose tests
serialize on the single vTPM through `serial_test`, whose locks are
in-process; nextest runs every test in its own process in parallel.

CI runs these as the two test steps of the `attestation_service_tdx_tests`
job in `.github/workflows/ci.yml` — one job, so the suites share a single
dependency build on the TDX runner.
