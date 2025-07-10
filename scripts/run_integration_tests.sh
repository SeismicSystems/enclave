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

# Build contracts
echo "🔨 Building smart contracts..."
cd crates/enclave-contract/contracts
chmod +x build.sh
./build.sh
cd ../../..

# Setup test directories
echo "📁 Setting up test directories..."
sudo mkdir -p /home/azureuser/.reth/db
sudo mkdir -p /mnt/datadisk
sudo mkdir -p /tmp/snapshot
# Create a dummy mdbx.dat file for tests
sudo touch /home/azureuser/.reth/db/mdbx.dat
sudo chown -R azureuser:azureuser /home/azureuser/.reth
sudo chown -R azureuser:azureuser /mnt/datadisk
sudo chown -R azureuser:azureuser /tmp/snapshot

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
if ! cargo test test_multisig_upgrade_operator_workflow -- --nocapture; then
    echo "❌ test_multisig_upgrade_operator_workflow failed"
    exit 1
fi
echo "✅ test_multisig_upgrade_operator_workflow passed"

# Test 2: Run boot share root key test
echo "🧪 Running test_boot_share_root_key..."
cd ../enclave-server
if ! cargo test test_boot_share_root_key -- --nocapture; then
    echo "❌ test_boot_share_root_key failed"
    exit 1
fi
echo "✅ test_boot_share_root_key passed"

# Test 3: Run snapshot integration handlers test
echo "🧪 Running test_snapshot_integration_handlers..."
if ! cargo test test_snapshot_integration_handlers -- --nocapture; then
    echo "❌ test_snapshot_integration_handlers failed"
    exit 1
fi
echo "✅ test_snapshot_integration_handlers passed"

echo "🎉 All integration tests passed!" 