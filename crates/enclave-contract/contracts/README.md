# Creating the Contract ABI
From the root of the enclave repo:
```
sforge inspect crates/enclave-server/src/snapshot/contracts/UpgradeOperator.sol:UpgradeOperator abi > crates/enclave-server/src/snapshot/contracts/UpgradeOperatorAbi.json
```

# Creating the Contract Json / Bytecode
Create a forge project and build the contract:
```
forge build
```

The resulting `out` directory contains the `UpgradeOperator.json` file, which contains the contract's bytecode and ABI.

# Building Contracts for Testing
Run the `build.sh` script to build the contracts without setting up a forge project. Contract jsons are copied to `crates/enclave-server/tests/integration/snapshot`

# Contract Overview

## UpgradeOperator
The main contract that handles upgrade validation logic. It stores RTMR (Runtime Measurement Register) values and provides functions to set and get MRTD (Measurement Root Trust Data) status.

## UpgradeOperatorFactory
A factory contract that uses CREATE2 to deploy UpgradeOperator contracts at predictable addresses. This allows for deterministic contract deployment based on salt values.

### Key Features:
- `deployUpgradeOperator(bytes32 salt)`: Deploys a new UpgradeOperator contract using CREATE2
- `computeAddress(bytes32 salt)`: Computes the address where a contract will be deployed
- `isDeployed(address contractAddress)`: Checks if a contract has been deployed at a given address

### CREATE2 Address Calculation
The CREATE2 address is computed using the formula:
```
address = keccak256(0xff ++ factory_address ++ salt ++ keccak256(contract_bytecode))[12:]
```

This ensures that the same contract deployed with the same salt will always have the same address, regardless of who deploys it or when.

**Factors that DO affect the CREATE2 address:**
1. **Factory address** - The address of the contract that calls CREATE2
2. **Salt** - The 32-byte salt value you provide
3. **Contract bytecode** - The creation code of the contract being deployed

**Factors that DON'T affect the CREATE2 address:**
1. **msg.sender** - The address calling the factory doesn't matter