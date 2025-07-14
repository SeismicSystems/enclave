# Integration Tests

This directory contains scripts for running integration tests for the Seismic enclave system.

## Integration Test Runner

The `run_integration_tests.sh` script runs three integration tests in the correct order:

1. **test_multisig_upgrade_operator_workflow** - Sets up the upgrade operator contract and multisig workflow
2. **test_boot_share_root_key** - Tests the boot process for sharing root keys (requires setup from test 1)
3. **test_snapshot_integration_handlers** - Tests snapshot creation and restoration functionality

## Prerequisites

The integration tests require:

- **Supervisor** - Process management for the reth and enclave-server services
- **Rust toolchain** - For building and running the tests
- **Sudo privileges** - For managing services and directories

## Test Dependencies

### test_multisig_upgrade_operator_workflow
- **Location**: `crates/enclave-contract/tests/multisig_test.rs`
- **Purpose**: Tests the complete multisig workflow for controlling the UpgradeOperator contract
- **Dependencies**: Reth service running via supervisor

### test_boot_share_root_key
- **Location**: `crates/enclave-server/tests/integration/booter.rs`
- **Purpose**: Tests the boot process for sharing root keys between enclave instances
- **Dependencies**: 
  - Reth service running via supervisor
  - Enclave-server service NOT running
  - Upgrade operator setup from test_multisig_upgrade_operator_workflow
  - sudo privileges

### test_snapshot_integration_handlers
- **Location**: `crates/enclave-server/tests/integration/snapshot.rs`
- **Purpose**: Tests encrypted snapshot creation and restoration functionality
- **Dependencies**:
  - Reth service running via supervisor
  - Enclave server running on default endpoint
  - sudo priviliges

## Directory Structure

The tests expect the following directory structure:

```
/home/azureuser/.reth/db/mdbx.dat  # Reth database file
/mnt/datadisk/                     # Data disk for snapshots
/tmp/snapshot/                     # Temporary snapshot directory
```

## Running the Tests

### In CI
The integration tests are automatically run in the CI pipeline via the `integration_tests` job in `.github/workflows/ci.yml`. The CI workflow:

1. Downloads pre-built enclave binaries from artifacts
2. Builds seismic-reth binary
3. Sets up Rust environment and PATH
4. Runs the integration test script

### Locally
To run the integration tests locally:

```bash
# Make the script executable
chmod +x scripts/run_integration_tests.sh

# Run the tests
./scripts/run_integration_tests.sh
```
