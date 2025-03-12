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