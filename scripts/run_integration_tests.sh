#!/bin/bash

# Integration test runner script
# This script runs the three integration tests in the correct order:
# 1. test_multisig_upgrade_operator_workflow (also sets up the upgrade operator to accpet attestations from devbox)
# 2. test_boot_share_root_key (requires the setup from step 1)
# 3. test_snapshot_integration_handlers (can run independently)

set -e

# Set environment variables for better debugging
export RUST_BACKTRACE=1
export RUST_LOG=info

echo "🚀 Starting integration tests..."

# Function to cleanup processes
cleanup() {
    echo "🧹 Cleaning up processes..."
    sudo supervisorctl stop all || true
}

# Set up trap to cleanup on exit
trap cleanup EXIT

# Install dependencies if not already installed
echo "📦 Installing dependencies..."
sudo apt-get update
sudo apt-get install -y supervisor tar lz4 curl

# Start services via supervisor
echo "🔧 Starting supervisor services..."
sudo supervisorctl start all || true
sleep 10

# Check if reth is running
echo "🔍 Checking if reth is running..."
if ! sudo supervisorctl status reth | grep -q "RUNNING"; then
    echo "❌ Failed to start reth service"
    exit 1
fi
echo "✅ reth service is running"

# Test 1: Run multisig upgrade operator workflow test
echo "🧪 Running test_multisig_upgrade_operator_workflow..."
cd crates/enclave-contract
# Build tests and get binary paths
OUTPUT=$(cargo test --no-run 2>&1)
echo "$OUTPUT"
mapfile -t binaries < <(echo "$OUTPUT" | grep -o '/[^ ]*enclave_contract-[a-z0-9]*')
if [ ${#binaries[@]} -eq 0 ]; then
    echo "❌ Could not find enclave-contract test binaries"
    exit 1
fi
echo "Found binaries: ${binaries[*]}"
# Run the first binary with the specific test
if ! "${binaries[0]}" test_multisig_upgrade_operator_workflow; then
    echo "❌ test_multisig_upgrade_operator_workflow failed"
    exit 1
fi
echo "✅ test_multisig_upgrade_operator_workflow passed"

# Test 2: Run boot share root key test
echo "🧪 Running test_boot_share_root_key..."
cd ../enclave-server
# Build tests and get binary paths
OUTPUT=$(cargo test --no-run 2>&1)
echo "$OUTPUT"
mapfile -t binaries < <(echo "$OUTPUT" | grep -o '/[^ ]*seismic_enclave_server-[a-z0-9]*')
if [ ${#binaries[@]} -eq 0 ]; then
    echo "❌ Could not find seismic-enclave-server test binaries"
    exit 1
fi
echo "Found binaries: ${binaries[*]}"
# Run the first binary with the specific test
if ! "${binaries[0]}" test_boot_share_root_key; then
    echo "❌ test_boot_share_root_key failed"
    exit 1
fi
echo "✅ test_boot_share_root_key passed"

# Test 3: Run snapshot integration handlers test
echo "🧪 Running test_snapshot_integration_handlers..."
if ! "${binaries[0]}" test_snapshot_integration_handlers; then
    echo "❌ test_snapshot_integration_handlers failed"
    exit 1
fi
echo "✅ test_snapshot_integration_handlers passed"

echo "🎉 All integration tests passed!" 