# Enclave Contract

This crate provides smart contracts relevant to enclave functionality and utilities for deploying and interacting with them.

## Overview

The `enclave-contract` crate centralizes all contract-related functionality for the Seismic enclave system, including:

- The **UpgradeOperator** contract, which manages defining attributes (MRTD, MRSEAM, PCR4) for upgrade validation
- The **MultisigUpgradeOperator** contract, which provides 2-of-3 voting control over the UpgradeOperator
- The **UpgradeOperatorFactory** contract for CREATE2 deployment of both contracts
- Contract deployment utilities (CREATE2 via factory for consistent contract addresses)
- Contract interaction functions for proposal creation, voting, and execution
- Testing utilities for contract operations

## Features

### Smart Contracts
- **UpgradeOperator** - Manages defining attributes (MRTD, MRSEAM, PCR4) for upgrade validation with owner-based access control
- **MultisigUpgradeOperator** - 2-of-3 multisig contract that controls UpgradeOperator through voting mechanism
- **UpgradeOperatorFactory** - Factory contract for CREATE2 deployment of both UpgradeOperator and MultisigUpgradeOperator instances

### Contract Deployment
- `deploy_factory()` - Deploy factory contracts for CREATE2 operations
- `deploy_via_factory_create2()` - Deploy UpgradeOperator using CREATE2 through a factory
- `deploy_upgrade_operator_with_multisig()` - Deploy both UpgradeOperator and MultisigUpgradeOperator with proper ownership setup
- `upgrades_canonical_deploy()` - Deploy the canonical upgrade contracts using predefined addresses
- `send_eth()` - Send ETH transactions (useful for testing)

### Contract Interaction
- `create_multisig_proposal()` - Create a proposal in the MultisigUpgradeOperator
- `vote_on_multisig_proposal()` - Vote on a proposal (requires one of the three signers)
- `execute_multisig_proposal()` - Execute a proposal if it has sufficient votes
- `can_execute_multisig_proposal()` - Check if a proposal can be executed
- `get_multisig_vote_count()` - Get the current vote count for a proposal
- `check_proposal_status_v1()` - Check the status of defining attributes in UpgradeOperator
- `compute_create2_address()` - Compute CREATE2 addresses without deploying

### Testing Utilities
- Anvil test keys for local development (`ANVIL_ALICE_SK`, `ANVIL_BOB_SK`, `ANVIL_CHARLIE_SK`)
- Predefined contract addresses (`UPGRADE_OPERATOR_ADDRESS`, `UPGRADE_MULTISIG_ADDRESS`)
- `ProposalParamsV1` struct for managing proposal parameters
- `print_flush()` utility for immediate output during tests

## Usage

### CREATE2 Deployment of UpgradeOperator and MultisigUpgradeOperator
```rust
use enclave_contract::{deploy_factory, deploy_upgrade_operator_with_multisig, ANVIL_ALICE_SK};

// Deploy the factory first
let factory_address = deploy_factory(
    "contracts/out/UpgradeOperatorFactory.sol/UpgradeOperatorFactory.json",
    ANVIL_ALICE_SK,
    "http://localhost:8545"
).await?;

// Deploy both contracts using CREATE2
let upgrade_operator_salt = [0x01; 32];
let multisig_salt = [0x02; 32];
let (operator_address, multisig_address) = deploy_upgrade_operator_with_multisig(
    factory_address,
    ANVIL_ALICE_SK,
    "http://localhost:8545",
    upgrade_operator_salt,
    multisig_salt
).await?;
```

### Multisig Proposal Workflow
```rust
use enclave_contract::{
    create_multisig_proposal, vote_on_multisig_proposal, execute_multisig_proposal,
    ProposalParamsV1, ANVIL_ALICE_SK, ANVIL_BOB_SK
};

// Create proposal parameters
let params = ProposalParamsV1::test_params();
let status = true;

// Create a proposal
let (proposal_id, nonce) = create_multisig_proposal(
    multisig_address,
    ANVIL_ALICE_SK,
    "http://localhost:8545",
    &params,
    status
).await?;

// Vote on the proposal (requires 2-of-3 votes)
vote_on_multisig_proposal(
    multisig_address,
    ANVIL_ALICE_SK,
    "http://localhost:8545",
    proposal_id,
    true
).await?;

vote_on_multisig_proposal(
    multisig_address,
    ANVIL_BOB_SK,
    "http://localhost:8545",
    proposal_id,
    true
).await?;

// Execute the proposal
execute_multisig_proposal(
    multisig_address,
    ANVIL_ALICE_SK,
    "http://localhost:8545",
    &params,
    status,
    nonce
).await?;
```

### Checking Proposal Status
```rust
use enclave_contract::{check_proposal_status_v1, ProposalParamsV1};

// Check if defining attributes are approved
let params = ProposalParamsV1::test_params();
let is_approved = check_proposal_status_v1(
    upgrade_operator_address,
    "http://localhost:8545",
    &params
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
2. Generate JSON artifacts in `contracts/out/`
3. Copy the generated JSON files to `tests/integration/` for testing

## Testing

Run the integration tests:

```bash
cargo test -p enclave-contract
```

The tests verify:
- CREATE2 deployment consistency
- Complete multisig workflow (proposal creation, voting, execution)
- Contract interactions and state changes
- 2-of-3 voting mechanism functionality

## Contract Architecture

### UpgradeOperator
- Manages defining attributes (MRTD: 48 bytes, MRSEAM: 48 bytes, PCR4: 32 bytes)
- Owner-based access control for setting attribute status
- Computes unique IDs for attribute combinations using keccak256

### MultisigUpgradeOperator
- 2-of-3 voting mechanism using Anvil test keys (Alice, Bob, Charlie)
- Controls UpgradeOperator through proposal and execution workflow
- Uses nonce-based proposal IDs for uniqueness
- Requires 2 approvals to execute proposals

### UpgradeOperatorFactory
- CREATE2 deployment for predictable contract addresses
- Supports deployment of both individual contracts and paired deployments
- Tracks deployed contracts for verification