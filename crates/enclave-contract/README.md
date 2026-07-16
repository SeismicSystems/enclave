# Enclave Contract

This crate provides smart contracts relevant to enclave functionality and utilities for interacting with them.

## Overview

The `enclave-contract` crate centralizes all contract-related functionality for the Seismic enclave system, including:

- The **UpgradeOperator** contract, which manages defining attributes (MRTD, MRSEAM, PCR4) for upgrade validation
- The **MultisigUpgradeOperator** contract, which provides 2-of-3 voting control over the UpgradeOperator
- Contract interaction functions for proposal creation, voting, and execution
- Testing utilities for contract operations

## TODO: update measurement policy for Azure and GCP

The current `UpgradeOperator.Measurements` shape and README language are stale for the attestation model we now need to support. Today the contract stores:

```solidity
struct Measurements {
    string tag;
    bytes mrtd;
    bytes mrseam;
    uint8[] registrar_slots;
    bytes[] registrar_values;
}
```

and the attestation service currently fills it from raw TDX quote fields (`MRTD`, `MRSEAM`, `RTMR0..3`). That is not sufficient as a cross-cloud or Azure production guest-image policy.

Required direction:

- **Azure TDX CVMs:** Azure uses Microsoft OpenHCL/OpenVMM/paravisor plus nested virtualization. Raw TDX `MRTD`/`RTMR*` primarily identify the Azure paravisor/platform layer, not the Seismic guest image. The guest image policy should be based on Azure vTPM PCR measurements, expected to be PCR 4, PCR 9, and PCR 11 from `seismic-images make measure`, verified through vTPM quote + AK certificate/HCL/TDX binding or equivalent MAA claims.
- **GCP TDX CVMs:** GCP exposes native TDX-style measurements. `seismic-images make measure-gcp` currently emits a policy containing `mrtd`, `rtmr0`, `rtmr1`, `rtmr2`, `rtmr3`, `mrconfigid`, `xfam`, and `tdattributes`. Some fields can be arrays because multiple firmware / RTMR0 values may be accepted for one image and machine configuration.
- **Contract/API redesign:** replace or version `Measurements` so policy records carry an attestation kind, e.g. `azure-vtpm` vs `gcp-tdx`, and store the appropriate register namespace for each kind. Do not overload `registrar_slots` to mean both Azure PCRs and TDX RTMRs without an explicit kind/version.
- **Upgrade flow:** update `MultisigUpgradeOperator` proposals, Rust bindings, attestation-service verification, tests, and genesis initial measurements once the new policy type is chosen.

Possible shape:

```solidity
enum AttestationKind {
    AzureVtpm,
    GcpTdx,
    DcapTdx
}

struct MeasurementPolicy {
    string tag;
    AttestationKind kind;
    uint16[] slots;
    bytes[] values;
    bytes extra; // optional encoded mrtd/mrseam/xfam/tdattributes/etc.
}
```

The final shape should be chosen together with `seismic-attestation` evidence types so the same policy can be used by deploy tooling, root-key bootstrap, and TxSeismic clients.

## Features

### Smart Contracts
- **UpgradeOperator** - Manages defining attributes (MRTD, MRSEAM, PCR4) for upgrade validation with owner-based access control
- **MultisigUpgradeOperator** - 2-of-3 multisig contract that controls UpgradeOperator through voting mechanism

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

### Multisig Proposal Workflow
```rust
use enclave_contract::{
    create_multisig_proposal, vote_on_multisig_proposal, execute_multisig_proposal,
    ProposalParamsV1, ANVIL_ALICE_SK, ANVIL_BOB_SK, UPGRADE_MULTISIG_ADDRESS
};

// Parse the multisig address
let multisig_address = UPGRADE_MULTISIG_ADDRESS
    .parse::<alloy::primitives::Address>()
    .unwrap();

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
use enclave_contract::{check_proposal_status_v1, ProposalParamsV1, UPGRADE_OPERATOR_ADDRESS};

// Parse the upgrade operator address
let upgrade_operator_address = UPGRADE_OPERATOR_ADDRESS
    .parse::<alloy::primitives::Address>()
    .unwrap();

// Check if defining attributes are approved
let params = ProposalParamsV1::test_params();
let is_approved = check_proposal_status_v1(
    upgrade_operator_address,
    "http://localhost:8545",
    &params
).await?;
```

### Vote Counting and Execution Checks
```rust
use enclave_contract::{
    get_multisig_vote_count, can_execute_multisig_proposal, UPGRADE_MULTISIG_ADDRESS
};

let multisig_address = UPGRADE_MULTISIG_ADDRESS
    .parse::<alloy::primitives::Address>()
    .unwrap();

// Get current vote count for a proposal
let (approval_count, total_votes) = get_multisig_vote_count(
    multisig_address,
    "http://localhost:8545",
    proposal_id
).await?;

// Check if proposal can be executed
let can_execute = can_execute_multisig_proposal(
    multisig_address,
    "http://localhost:8545",
    proposal_id
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

## Testing

Run the integration tests:

```bash
cargo test -p enclave-contract
```

The tests verify:
- Complete multisig workflow (proposal creation, voting, execution)
- Contract interactions and state changes
- 2-of-3 voting mechanism functionality

## Contract Architecture

### UpgradeOperator
- Manages defining attributes (MRTD: 48 bytes, MRSEAM: 48 bytes, PCR4: 32 bytes)
- Owner-based access control for setting attribute status
- Computes unique IDs for attribute combinations using keccak256
- Deployed at genesis by seismic-reth at address `0x1000000000000000000000000000000000000001`

### MultisigUpgradeOperator
- 2-of-3 voting mechanism using Anvil test keys (Alice, Bob, Charlie)
- Controls UpgradeOperator through proposal and execution workflow
- Uses nonce-based proposal IDs for uniqueness
- Requires 2 approvals to execute proposals
- Deployed at genesis by seismic-reth at address `0x1000000000000000000000000000000000000002`

## Contract Addresses

The contracts are deployed at genesis by seismic-reth at predefined addresses:

- **UpgradeOperator**: `0x1000000000000000000000000000000000000001`
- **MultisigUpgradeOperator**: `0x1000000000000000000000000000000000000002`

## Test Keys

The crate provides Anvil test keys for local development:

- **Alice**: `0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80`
- **Bob**: `0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d`
- **Charlie**: `0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a`

These keys correspond to the three signers in the MultisigUpgradeOperator contract.