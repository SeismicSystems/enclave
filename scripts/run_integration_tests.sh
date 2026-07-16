#!/bin/bash

# Self-hosted integration test runner. The test needs direct TPM access plus
# the image's /run/seismic layout, so build as the runner user and execute the
# resulting test binary with sudo.

set -e

export RUST_BACKTRACE=1
export RUST_LOG=info

echo "🚀 Starting attestation-service integration tests..."

# The image service normally creates these runtime directories. Ensure they
# also exist when the test job starts from a clean runner boot.
sudo install -d -m 0755 /run/seismic/conf
sudo install -m 0644 \
    crates/network-manifest/fixtures/network-manifest-v1.json \
    /run/seismic/conf/network-manifest.json

# Free the TPM before the test starts its two node pairs. Seismic images may
# have a Supervisor-managed server; stock CI runners do not. The Supervisor
# program keeps its deployed name (enclave-server) until the runner image is
# regenerated with the split services.
if command -v supervisorctl >/dev/null 2>&1 && \
    sudo supervisorctl status enclave-server >/dev/null 2>&1; then
    sudo supervisorctl stop enclave-server
else
    echo "ℹ️ No running Supervisor-managed enclave-server to stop."
fi
sleep 2

cd bin/attestation-service
OUTPUT=$(CARGO_TERM_COLOR=never cargo test --test integration --no-run 2>&1)
echo "$OUTPUT"
mapfile -t binaries < <(echo "$OUTPUT" | sed -nE 's/^[[:space:]]*Executable .*\((.+)\)$/\1/p')
if [ ${#binaries[@]} -eq 0 ]; then
    echo "❌ Could not find the attestation-service integration test binary"
    exit 1
fi

for binary in "${binaries[@]}"; do
    echo "🚀 Executing: sudo $binary test_get_wrapped_root_key_bootstrap"
    sudo "$binary" test_get_wrapped_root_key_bootstrap
done

echo "🎉 All attestation-service integration tests passed!"
