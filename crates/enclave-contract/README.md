# Enclave Contract

This crate provides smart contracts relevant to enclave functionality and utilities for deploying and interacting with them.

## Overview

The `enclave-contract` crate centralizes all contract-related functionality for the Seismic enclave system, including:

- The UpgradeOperator contract, which tracks which nodes may access state data during network upgrades
- Contract deployment utilities (CREATE2 via factory for consistent contract address)
- Contract interaction functions
- Testing utilities for contract operations

## Features

### Smart Contracts
- **UpgradeOperator** - Tracks which nodes may access state data during network upgrades
- **UpgradeOperatorFactory** - Factory contract for CREATE2 deployment of UpgradeOperator instances

### Contract Deployment
- `deploy_factory()` - Deploy factory contracts for CREATE2 operations
- `deploy_via_factory_create2()` - Deploy contracts using CREATE2 through a factory
- `send_eth()` - Send ETH transactions (useful for testing)

### Contract Interaction
- `provider_check_mrtd()` - Interact with UpgradeOperator contracts to verify upgrade permissions
- `compute_create2_address()` - Compute CREATE2 addresses without deploying

### Testing Utilities
- Anvil test keys for local development (`ANVIL_ALICE_SK`, `ANVIL_BOB_SK`, `ANVIL_CHARLIE_SK`)

## Usage

### CREATE2 Deployment of UpgradeOperator
```rust
use enclave_contract::{deploy_factory, deploy_via_factory_create2, ANVIL_ALICE_SK};

// Deploy the factory first
let factory_address = deploy_factory(
    "contracts/out/UpgradeOperatorFactory.sol/UpgradeOperatorFactory.json",
    ANVIL_ALICE_SK,
    "http://localhost:8545"
).await?;

// Deploy UpgradeOperator using CREATE2
let salt = [0x01; 32];
let operator_address = deploy_via_factory_create2(
    factory_address,
    ANVIL_ALICE_SK,
    "http://localhost:8545",
    salt
).await?;
```

### Interacting with UpgradeOperator
```rust
use enclave_contract::{provider_check_mrtd, ANVIL_ALICE_SK};
use alloy::primitives::Bytes;

// Check if a node has permission to access state data during upgrades
let rootfs_hash = Bytes::from(vec![0x00; 32]);
let mrtd = Bytes::from(vec![0x00; 48]);
let rtmr0 = Bytes::from(vec![0x00; 48]);
let rtmr3 = Bytes::from(vec![0x00; 48]);

let has_permission = provider_check_mrtd(rootfs_hash, mrtd, rtmr0, rtmr3).await?;
```

## Building Contracts

To build the contracts and generate the necessary JSON files:

```bash
cd crates/enclave-contract
./build.sh
```

This will:
1. Build the contracts using `sforge`
2. Generate JSON artifacts in `contracts/out/`
3. Copy the generated JSON files to `tests/integration/` for testing

## Testing

Run the integration tests:

```bash
cargo test -p enclave-contract
```

The tests verify CREATE2 deployment consistency and contract interactions.