#!/bin/bash

# Self-hosted runner for the attestation service's reth-backed admission
# test suite
# (bin/attestation-service/tests/admission.rs). The tests need direct TPM
# access, the image's /run/seismic layout, and a seismic-reth binary
# (SEISMIC_RETH_BIN — CI installs it via setup-sreth), so build as the runner
# user and execute the resulting test binary with sudo.

set -e

export RUST_BACKTRACE=1
export RUST_LOG=info

echo "🚀 Starting attestation-service admission tests..."

# The image service normally creates these runtime directories. Ensure they
# also exist when the test job starts from a clean runner boot. The manifest
# that lands here is written by the tests themselves: each one pins the genesis
# of the node it just generated, so only the test can render it.
sudo install -d -m 0755 /run/seismic/conf

# Free the TPM before the tests start their handshakes: quote generation
# opens the raw TPM device (/dev/tpm0), which the kernel hands to one process
# at a time (tpmrm0 support is kinvolk/azure-cvm-tooling#92). Seismic images
# may have a Supervisor-managed server; stock CI runners do not. The
# Supervisor program keeps its deployed name (enclave-server) until the
# runner image is regenerated with the split services.
if command -v supervisorctl >/dev/null 2>&1 && \
    sudo supervisorctl status enclave-server >/dev/null 2>&1; then
    sudo supervisorctl stop enclave-server
else
    echo "ℹ️ No running Supervisor-managed enclave-server to stop."
fi
sleep 2

cd bin/attestation-service
OUTPUT=$(CARGO_TERM_COLOR=never cargo test --test admission --no-run 2>&1)
echo "$OUTPUT"
mapfile -t binaries < <(echo "$OUTPUT" | sed -nE 's/^[[:space:]]*Executable .*\((.+)\)$/\1/p')
if [ ${#binaries[@]} -eq 0 ]; then
    echo "❌ Could not find the attestation-service admission test binary"
    exit 1
fi

# The target compiles to one test binary that runs every test in a single
# process, serialized around the runner's single vTPM by serial_test — no
# filtering or thread capping needed. The loop only covers cargo ever listing
# more executables. sudo strips the environment, so pass the log/backtrace
# config and the reth binary location through explicitly.
for binary in "${binaries[@]}"; do
    echo "🚀 Executing: sudo $binary"
    sudo env RUST_LOG="$RUST_LOG" RUST_BACKTRACE="$RUST_BACKTRACE" \
        SEISMIC_RETH_BIN="${SEISMIC_RETH_BIN:-}" PATH="$PATH" \
        "$binary"
done

echo "🎉 All attestation-service admission tests passed!"
