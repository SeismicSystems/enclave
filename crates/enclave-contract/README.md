# Enclave Contract

This crate provides utilities for deploying and interacting with smart contracts in the Seismic enclave system.

## Overview

The `enclave-contract` crate centralizes all contract-related functionality, including:

- Smart contract deployment utilities
- CREATE2 deployment through factory contracts
- Contract interaction functions
- Testing utilities for contract operations

## Features

### Contract Deployment
- `deploy_contract()` - Deploy contracts using standard CREATE
- `deploy_factory()` - Deploy factory contracts for CREATE2 operations
- `deploy_via_factory_create2()` - Deploy contracts using CREATE2 through a factory

### Contract Interaction
- `check_operator()` - Interact with UpgradeOperator contracts
- `compute_create2_address()` - Compute CREATE2 addresses without deploying

### Testing Utilities
- `print_flush()` - Utility for immediate output during tests
- Anvil test keys for local development

## Usage

### Basic Contract Deployment
```rust
use enclave_contract::{deploy_contract, ANVIL_ALICE_SK};

let result = deploy_contract(
    "path/to/contract.json",
    ANVIL_ALICE_SK,
    "http://localhost:8545"
).await?;
```

### CREATE2 Deployment
```rust
use enclave_contract::{deploy_factory, deploy_via_factory_create2, ANVIL_ALICE_SK};

// Deploy the factory first
let factory_address = deploy_factory(
    "path/to/factory.json",
    ANVIL_ALICE_SK,
    "http://localhost:8545"
).await?;

// Deploy using CREATE2
let salt = [0x01; 32];
let contract_address = deploy_via_factory_create2(
    factory_address,
    ANVIL_ALICE_SK,
    "http://localhost:8545",
    salt
).await?;
```

## Building Contracts

To build the contracts and generate the necessary JSON files:

```bash
cd crates/enclave-contract
./build.sh
```

This will:
1. Build the contracts using `sforge`
2. Copy the generated JSON files to `tests/integration/`

## Testing

Run the integration tests:

```bash
cargo test -p enclave-contract
```

The tests verify CREATE2 deployment consistency and contract interactions.

## Dependencies

- `alloy` - Ethereum development framework
- `anyhow` - Error handling
- `serde` - Serialization
- `tokio` - Async runtime 