# Integration Tests

This directory contains scripts for running integration tests for the Seismic enclave system.

## Integration Test Runner

The `run_integration_tests.sh` script runs three integration tests in the correct order:

1. **test_multisig_upgrade_operator_workflow** - Sets up the upgrade operator contract and multisig workflow
2. **test_boot_share_root_key** - Tests the boot process for sharing root keys (requires setup from test 1)
3. **test_snapshot_integration_handlers** - Tests snapshot creation and restoration functionality

## Prerequisites

The integration tests require:

- **Anvil** - Local Ethereum development environment
- **Supervisor** - Process management for the reth service
- **Rust toolchain** - For building and running the tests
- **Sudo privileges** - For managing services and directories

## Test Dependencies

### test_multisig_upgrade_operator_workflow
- **Location**: `crates/enclave-contract/tests/multisig_test.rs`
- **Purpose**: Tests the complete multisig workflow for controlling the UpgradeOperator contract
- **Dependencies**: Anvil blockchain running on localhost:8545
- **Setup**: Builds smart contracts using sforge

### test_boot_share_root_key
- **Location**: `crates/enclave-server/tests/integration/booter.rs`
- **Purpose**: Tests the boot process for sharing root keys between enclave instances
- **Dependencies**: 
  - Anvil blockchain running on localhost:8545
  - Reth service running via supervisor
  - Upgrade operator setup from test_multisig_upgrade_operator_workflow
- **Setup**: Requires sudo privileges

### test_snapshot_integration_handlers
- **Location**: `crates/enclave-server/tests/integration/snapshot.rs`
- **Purpose**: Tests encrypted snapshot creation and restoration functionality
- **Dependencies**:
  - Anvil blockchain running on localhost:8545
  - Reth service running via supervisor
  - Enclave server running on default endpoint
- **Setup**: Requires sudo privileges and specific directory structure

## Directory Structure

The tests expect the following directory structure:

```
/home/azureuser/.reth/db/mdbx.dat  # Reth database file
/mnt/datadisk/                     # Data disk for snapshots
/tmp/snapshot/                     # Temporary snapshot directory
```

## Running the Tests

### In CI
The integration tests are automatically run in the CI pipeline via the `integration_tests` job in `.github/workflows/ci.yml`.

### Locally
To run the integration tests locally:

```bash
# Make the script executable
chmod +x scripts/run_integration_tests.sh

# Run the tests
./scripts/run_integration_tests.sh
```

### Individual Tests
To run individual tests:

```bash
# Run multisig test
cd crates/enclave-contract
cargo test test_multisig_upgrade_operator_workflow -- --nocapture

# Run boot test (requires multisig test to run first)
cd ../enclave-server
cargo test test_boot_share_root_key -- --nocapture

# Run snapshot test
cargo test test_snapshot_integration_handlers -- --nocapture
```

## Troubleshooting

### Common Issues

1. **Anvil not starting**: Check if port 8545 is available
2. **Reth service not running**: Check supervisor configuration
3. **Permission denied**: Ensure script is run with sudo privileges
4. **Directory not found**: Ensure required directories exist and have correct permissions

### Debugging

The script sets the following environment variables for debugging:
- `RUST_BACKTRACE=1` - Enables full backtraces
- `RUST_LOG=info` - Enables info-level logging

Check the logs in `anvil.log` and `enclave-server.log` for additional debugging information. 