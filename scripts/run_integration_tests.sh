#!/bin/bash

# Integration test runner script
# This script runs the three integration tests in the correct order:
# 1. test_multisig_upgrade_operator_workflow (also sets up the upgrade operator to accpet attestations from devbox)
# 2. test_boot_share_root_key (requires the setup from step 1)
# 3. test_snapshot_integration_handlers (can run independently)

# set -e

# Set environment variables for better debugging
export RUST_BACKTRACE=1
export RUST_LOG=info

echo "🚀 Starting integration tests..."

# Function to cleanup processes
cleanup() {
    echo "🧹 Cleaning up processes..."
    echo $(sudo supervisorctl status)
    sudo supervisorctl stop all || true
    # Logs are stored elsewhere:
    # ~/.reth-logs and /var/log/reth.{out,err}.log
    sudo rm -rf /home/azureuser/.reth/
}

# # Set up trap to cleanup on exit
trap cleanup EXIT

# Make sure enclave is running so we can start reth
sudo supervisorctl start enclave-server || true
sleep 10

# Start services via supervisor
echo "🔧 Starting supervisor services..."
sudo supervisorctl start reth || true
sleep 10

# Make sure enclave is NOT running so we can access TPM in test
sudo supervisorctl stop enclave-server || true
sleep 2

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
mapfile -t binaries < <(echo "$OUTPUT" | grep -o '/[^ ]*multisig_test-[a-z0-9]*')
if [ ${#binaries[@]} -eq 0 ]; then
    echo "❌ Could not find multisig_test binaries"
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
ls -la Cargo.toml 2>/dev/null || echo "❌ Cargo.toml not found in $(pwd)"

# Build tests and get binary paths
OUTPUT=$(cargo test --no-run 2>&1)
echo "$OUTPUT"
mapfile -t binaries < <(echo "$OUTPUT" | grep -o '/[^ ]*integration-[a-z0-9]*')
if [ ${#binaries[@]} -eq 0 ]; then
    echo "❌ Could not find enclave-server integration test binaries"
    exit 1
fi
echo "Found binaries: ${binaries[*]}"
# Run the first binary with the specific test
sleep 2

echo "🚀 Executing: sudo ${binaries[0]} test_boot_share_root_key"
if ! sudo "${binaries[0]}" test_boot_share_root_key; then
    echo "❌ test_boot_share_root_key failed with exit code $?"
    echo "🔍 Last 20 lines of system log:"
    sudo journalctl -n 20 --no-pager 2>/dev/null || echo "Could not access journalctl"
    exit 1
fi
echo "✅ test_boot_share_root_key passed"

echo "🎉 All integration tests passed!" 