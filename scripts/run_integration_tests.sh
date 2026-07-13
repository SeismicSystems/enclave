#!/bin/bash

# Self-hosted integration test runner. The test needs direct TPM access plus
# the image's /run/seismic layout, so build as the runner user and execute the
# resulting test binary with sudo.

set -e

export RUST_BACKTRACE=1
export RUST_LOG=info

echo "🚀 Starting enclave-server integration tests..."

# The image service normally creates these runtime directories. Ensure they
# also exist when the test job starts from a clean runner boot.
sudo install -d -m 0755 /run/seismic/conf /run/seismic/enclave
sudo install -m 0644 \
    crates/network-manifest/fixtures/network-manifest-v1.json \
    /run/seismic/conf/network-manifest.json

# Free the TPM before the test starts two enclave-server instances.
sudo supervisorctl stop enclave-server || true
sleep 2

cd crates/enclave-server
OUTPUT=$(CARGO_TERM_COLOR=never cargo test --test integration --no-run 2>&1)
echo "$OUTPUT"
mapfile -t binaries < <(echo "$OUTPUT" | sed -nE 's/^[[:space:]]*Executable .*\((.+)\)$/\1/p')
if [ ${#binaries[@]} -eq 0 ]; then
    echo "❌ Could not find the enclave-server integration test binary"
    exit 1
fi

for binary in "${binaries[@]}"; do
    echo "🚀 Executing: sudo $binary test_get_wrapped_root_key_bootstrap"
    sudo "$binary" test_get_wrapped_root_key_bootstrap
done

echo "🎉 All enclave-server integration tests passed!"
