#!/bin/bash

# Integration test runner script (self-hosted; needs enclave-server + TPM + reth).
#
# The assertion-bearing multisig coverage now lives in the hosted `check_and_test`
# job (test_multisig_upgrade_operator_workflow against a throwaway anvil). Here we
# only need the multisig flow as on-chain SETUP: it writes the booter's measurement
# into the UpgradeOperator on the reth devnet, which test_boot_share_root_key reads
# at boot (enclave-server queries reth at :8545 for the allowlist — see
# crates/enclave-server/src/attestation/upgrade_contract.rs).
#
# Order matters: the multisig setup runs while reth + enclave-server are BOTH
# healthy, then enclave-server is stopped so the TPM is free for the boot test.
# (The old script ran the multisig step AFTER stopping enclave-server, by which
# point reth's RPC had dropped — that ConnectionRefused was the original failure.)
#
# 1. multisig setup           -> seed the UpgradeOperator allowlist on reth
# 2. test_boot_share_root_key -> needs enclave-server stopped (TPM) + the setup above
#
# KNOWN RESIDUAL (out of scope for this script, tracked separately):
# test_boot_share_root_key can still fail for two infra reasons unrelated to this
# script's structure:
#   (i)  enclave-server exiting at startup — it now requires a network manifest at
#        /run/seismic/conf/network-manifest.json; supervisor reports "Exited too
#        quickly" if deploy tooling hasn't dropped it.
#   (ii) reth must stay up at :8545 after enclave-server is stopped, but in the
#        current devnet reth does not survive losing enclave-server.

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

# Check if reth is running
echo "🔍 Checking if reth is running..."
if ! sudo supervisorctl status reth | grep -q "RUNNING"; then
    echo "❌ Failed to start reth service"
    exit 1
fi
echo "✅ reth service is running"


# Setup: run the multisig flow against reth (NOT a throwaway anvil) to write the
# booter's measurement into the UpgradeOperator allowlist that the boot test reads.
# MULTISIG_RPC points the test at reth and skips the anvil spawn + contract seeding
# (reth already has the contracts at genesis). Runs while enclave-server is still
# up, so reth's RPC is healthy.
echo "🧪 Setting up UpgradeOperator allowlist via multisig flow (against reth)..."
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
# Fail loudly if the allowlist write fails, so the boot test isn't silently unprepared.
if ! MULTISIG_RPC="http://localhost:8545" "${binaries[0]}" test_multisig_upgrade_operator_workflow; then
    echo "❌ multisig allowlist setup failed; aborting before boot test"
    exit 1
fi
echo "✅ UpgradeOperator allowlist setup complete"

# Now make sure enclave-server is NOT running so we can access the TPM in the boot test
sudo supervisorctl stop enclave-server || true
sleep 2

# Test: Run boot share root key test
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