# Building Contracts for Testing
Run the `build.sh` script to build the contracts. It should be run from this `contracts` folder.

# Contract Overview

## UpgradeOperator
The main contract that handles upgrade validation logic. It manages defining attributes (MRTD, MRSEAM, PCR4) for upgrade validation and provides functions to set and get their status.

### Key Features:
- **Owner-based Access Control**: Only the owner can set attribute status
- **Defining Attributes V1**: MRTD (48 bytes), MRSEAM (48 bytes), PCR4 (32 bytes)
- **Defining Attributes V2**: Extends V1 with PCR7 (32 bytes) for future use
- **Unique ID Computation**: Uses keccak256 to compute unique IDs for attribute combinations

### Key Functions:
- `set_id_status_v1(mrtd, mrseam, pcr4, status)`: Sets the status for V1 defining attributes (owner only)
- `get_id_status_v1(mrtd, mrseam, pcr4)`: Gets the status of V1 defining attributes
- `computeIdV1(attrs)`: Computes unique ID for V1 attributes
- `computeIdV2(attrs)`: Computes unique ID for V2 attributes
- `owner()`: Returns the contract owner address

## MultisigUpgradeOperator
A 2-of-3 multisig contract that controls the UpgradeOperator through a voting mechanism. It requires consensus from multiple signers before any changes can be made to the UpgradeOperator.

### Key Features:
- **2-of-3 Voting**: Requires 2 out of 3 signers to approve proposals
- **Anvil Test Signers**: Uses Alice, Bob, and Charlie from Anvil test keys
- **Nonce-based Proposals**: Each proposal uses an automatically incremented nonce for uniqueness
- **Proposal Workflow**: Create → Vote → Execute pattern

### Key Functions:
- `createProposalV1(mrtd, mrseam, pcr4, status)`: Creates a new proposal (auto-increments nonce)
- `vote(proposalId, approved)`: Allows signers to vote on proposals
- `executeProposalV1(mrtd, mrseam, pcr4, status, nonce)`: Executes approved proposals
- `getVoteCount(proposalId)`: Returns approval count and total votes
- `canExecute(proposalId)`: Checks if proposal has sufficient votes
- `computeProposalIdV1(mrtd, mrseam, pcr4, status, nonce)`: Computes proposal ID
- `proposalNonce()`: Returns current nonce counter

## UpgradeOperatorFactory
A factory contract that uses CREATE2 to deploy both UpgradeOperator and MultisigUpgradeOperator contracts at predictable addresses.

### Key Features:
- **CREATE2 Deployment**: Deterministic contract addresses based on salt values
- **Paired Deployment**: Can deploy both contracts together with proper ownership setup
- **Address Computation**: Predict contract addresses before deployment
- **Deployment Tracking**: Tracks deployed contracts for verification

### Key Functions:
- `deployUpgradeOperator(salt)`: Deploys UpgradeOperator with msg.sender as owner
- `deployUpgradeOperatorWithOwner(salt, owner)`: Deploys UpgradeOperator with specific owner
- `deployMultisigUpgradeOperator(salt, upgradeOperator)`: Deploys MultisigUpgradeOperator
- `deployUpgradeOperatorWithMultisig(upgradeOperatorSalt, multisigSalt)`: Deploys both contracts together
- `computeUpgradeOperatorAddress(salt)`: Computes UpgradeOperator address
- `computeUpgradeOperatorAddressWithOwner(salt, owner)`: Computes address with specific owner
- `computeMultisigUpgradeOperatorAddress(salt, upgradeOperator)`: Computes MultisigUpgradeOperator address
- `isDeployed(contractAddress)`: Checks if contract is deployed at address

### CREATE2 Address Calculation
The CREATE2 address is computed using the formula:
```
address = keccak256(0xff ++ factory_address ++ salt ++ keccak256(contract_bytecode))[12:]
```

This ensures that the same contract deployed with the same salt will always have the same address, regardless of who deploys it or when.

**Factors that DO affect the CREATE2 address:**
1. **Factory address** - The address of the contract that calls CREATE2
2. **Salt** - The 32-byte salt value you provide
3. **Contract bytecode** - The creation code of the contract being deployed (including constructor arguments)

**Factors that DON'T affect the CREATE2 address:**
1. **msg.sender** - The address calling the factory doesn't matter
2. **Gas price/limit** - Transaction parameters don't affect the address

## Contract Relationships

```
UpgradeOperatorFactory
├── UpgradeOperator (owned by MultisigUpgradeOperator)
└── MultisigUpgradeOperator (controls UpgradeOperator)
    ├── Signer1 (Alice)
    ├── Signer2 (Bob)
    └── Signer3 (Charlie)
```

## Deployment Workflow

1. **Deploy Factory**: Deploy UpgradeOperatorFactory using regular deployment
2. **Deploy Contracts**: Use factory to deploy both contracts with CREATE2
3. **Setup Ownership**: MultisigUpgradeOperator becomes owner of UpgradeOperator
4. **Configure Signers**: Three Anvil test keys are automatically set as signers

## Testing

The contracts are tested through the Rust integration tests in `tests/multisig_test.rs`, which verify:
- CREATE2 deployment consistency
- Complete multisig workflow (proposal creation, voting, execution)
- Contract interactions and state changes
- 2-of-3 voting mechanism functionality

For detailed multisig documentation, see [MULTISIG.md](./MULTISIG.md).