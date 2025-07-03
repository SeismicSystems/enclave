# TODO: This README is out of date

# MultisigUpgradeOperator Contract

This contract implements a 2-of-3 multisig control mechanism for the UpgradeOperator contract. It requires two out of three authorized signers to approve any MRTD (Measured Root of Trust for Dynamic Launch) changes.

## Overview

The MultisigUpgradeOperator contract acts as a proxy that controls the UpgradeOperator contract. Instead of having a single owner, it requires consensus from multiple signers before any changes can be made.

## Signers

The contract uses the three ANVIL test keys as signers:

- **Alice**: `0x70997970C51812dc3A010C7d01b50e0d17dc79C8`
- **Bob**: `0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC`
- **Charlie**: `0x90F79bf6EB2c4f870365E785982E1f101E93b906`

## Workflow

1. **Create Proposal**: Anyone can create a proposal to set MRTD values (includes automatic nonce increment)
2. **Vote**: The three signers can vote on the proposal (true/false)
3. **Execute**: Once 2 out of 3 signers approve, anyone can execute the proposal using the correct nonce
4. **Update**: The MRTD values are set in the underlying UpgradeOperator contract

## Key Functions

### `createProposal(rootfs_hash, mrtd, rtmr0, rtmr3, status)`
Creates a new proposal for setting MRTD values. Automatically increments the internal nonce counter and returns a unique proposal ID that includes the nonce.

### `vote(proposalId, approved)`
Allows a signer to vote on a proposal. Only the three authorized signers can vote.

### `executeProposal(rootfs_hash, mrtd, rtmr0, rtmr3, status, nonce)`
Executes a proposal if it has sufficient votes (2 out of 3). Requires the correct nonce that was used when creating the proposal. Calls the underlying UpgradeOperator's `set_mrtd` function.

### `getVoteCount(proposalId)`
Returns the number of approvals and total votes for a proposal.

### `canExecute(proposalId)`
Checks if a proposal has enough votes to be executed.

### `computeProposalId(rootfs_hash, mrtd, rtmr0, rtmr3, status, nonce)`
Computes the proposal ID for given parameters and nonce. Useful for verifying proposal IDs.

### `proposalNonce()`
Returns the current nonce counter value.

## Deployment

The contract is deployed through the `UpgradeOperatorFactory`:

```javascript
// Deploy both contracts together
const [upgradeOperatorAddress, multisigAddress] = await factory.deployUpgradeOperatorWithMultisig(
    upgradeOperatorSalt,
    multisigSalt
);
```

## Usage Example

```javascript
// 1. Create a proposal (nonce is automatically managed)
const proposalId = await multisig.createProposal(rootfs_hash, mrtd, rtmr0, rtmr3, true);

// 2. Get the nonce used for this proposal
const nonce = await multisig.proposalNonce();

// 3. Signers vote
await multisig.connect(alice).vote(proposalId, true);
await multisig.connect(bob).vote(proposalId, true);

// 4. Execute the proposal with the correct nonce
await multisig.executeProposal(rootfs_hash, mrtd, rtmr0, rtmr3, true, nonce);
```

## Rust Integration Example

```rust
// Create a proposal
let (proposal_id, nonce) = create_multisig_proposal(
    multisig_address,
    ANVIL_ALICE_SK,
    reth_rpc,
    rootfs_hash,
    mrtd,
    rtmr0,
    rtmr3,
    true,
).await?;

// Vote on the proposal
vote_on_multisig_proposal(multisig_address, ANVIL_ALICE_SK, reth_rpc, proposal_id, true).await?;
vote_on_multisig_proposal(multisig_address, ANVIL_BOB_SK, reth_rpc, proposal_id, true).await?;

// Execute the proposal with the nonce
execute_multisig_proposal(
    multisig_address,
    ANVIL_ALICE_SK,
    reth_rpc,
    rootfs_hash,
    mrtd,
    rtmr0,
    rtmr3,
    true,
    nonce,
).await?;
```

## Security Features

- **Immutable Signers**: The three signer addresses are set at deployment and cannot be changed
- **Nonce-based Uniqueness**: Each proposal uses an automatically incremented nonce to ensure uniqueness
- **Proposal Uniqueness**: Each proposal is uniquely identified by the hash of its parameters plus the nonce
- **No Double Voting**: Each signer can only vote once per proposal
- **Execution Protection**: Proposals can only be executed once with the correct nonce
- **Minimum Consensus**: Requires 2 out of 3 votes to execute
- **Replay Protection**: The nonce prevents replay attacks and ensures proposal uniqueness

## Events

- `ProposalCreated`: Emitted when a new proposal is created (includes nonce)
- `VoteCast`: Emitted when a signer votes on a proposal
- `ProposalExecuted`: Emitted when a proposal is successfully executed

## Testing

Run the test script to see the multisig in action:

```bash
cargo test test_multisig_upgrade_operator_workflow
```

This will deploy the contracts and demonstrate the complete workflow from proposal creation to execution with nonce management. 