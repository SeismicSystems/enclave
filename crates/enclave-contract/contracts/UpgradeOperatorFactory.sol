// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./UpgradeOperator.sol";
import "./MultisigUpgradeOperator.sol";

/**
 * @title UpgradeOperatorFactory
 * @dev Factory contract for deploying UpgradeOperator and MultisigUpgradeOperator contracts using CREATE2
 * This allows for predictable contract addresses based on salt values
 */
contract UpgradeOperatorFactory {
    
    // Mapping to track deployed contracts
    mapping(address => bool) public deployedContracts;
    
    // Event emitted when a new contract is deployed
    event ContractDeployed(address indexed contractAddress, bytes32 indexed salt, string contractType);
    
    /**
     * @dev Deploys a new UpgradeOperator contract using CREATE2
     * @param salt The salt value used for CREATE2 deployment
     * @return contractAddress The address of the deployed contract
     */
    function deployUpgradeOperator(bytes32 salt) public returns (address contractAddress) {
        // Create the contract bytecode
        bytes memory bytecode = type(UpgradeOperator).creationCode;
        
        // Deploy using CREATE2
        assembly {
            contractAddress := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
        }
        
        require(contractAddress != address(0), "Create2: Failed on deploy");
        
        // Track the deployed contract
        deployedContracts[contractAddress] = true;
        
        emit ContractDeployed(contractAddress, salt, "UpgradeOperator");
        
        return contractAddress;
    }
    
    /**
     * @dev Deploys a new MultisigUpgradeOperator contract using CREATE2
     * @param salt The salt value used for CREATE2 deployment
     * @param upgradeOperator The address of the UpgradeOperator to control
     * @return contractAddress The address of the deployed contract
     */
    function deployMultisigUpgradeOperator(bytes32 salt, address upgradeOperator) public returns (address contractAddress) {
        // Create the contract bytecode with constructor arguments
        bytes memory bytecode = abi.encodePacked(
            type(MultisigUpgradeOperator).creationCode,
            abi.encode(upgradeOperator)
        );
        
        // Deploy using CREATE2
        assembly {
            contractAddress := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
        }
        
        require(contractAddress != address(0), "Create2: Failed on deploy");
        
        // Track the deployed contract
        deployedContracts[contractAddress] = true;
        
        emit ContractDeployed(contractAddress, salt, "MultisigUpgradeOperator");
        
        return contractAddress;
    }
    
    /**
     * @dev Deploys both an UpgradeOperator and a MultisigUpgradeOperator that controls it
     * @param upgradeOperatorSalt The salt for the UpgradeOperator
     * @param multisigSalt The salt for the MultisigUpgradeOperator
     * @return upgradeOperatorAddress The address of the deployed UpgradeOperator
     * @return multisigAddress The address of the deployed MultisigUpgradeOperator
     */
    function deployUpgradeOperatorWithMultisig(
        bytes32 upgradeOperatorSalt,
        bytes32 multisigSalt
    ) public returns (address upgradeOperatorAddress, address multisigAddress) {
        // First deploy the UpgradeOperator
        upgradeOperatorAddress = deployUpgradeOperator(upgradeOperatorSalt);
        
        // Then deploy the MultisigUpgradeOperator that controls it
        multisigAddress = deployMultisigUpgradeOperator(multisigSalt, upgradeOperatorAddress);
        
        return (upgradeOperatorAddress, multisigAddress);
    }
    
    /**
     * @dev Computes the address where an UpgradeOperator contract will be deployed using CREATE2
     * @param salt The salt value used for CREATE2 deployment
     * @return The predicted contract address
     */
    function computeUpgradeOperatorAddress(bytes32 salt) public view returns (address) {
        bytes memory bytecode = type(UpgradeOperator).creationCode;
        bytes32 hash = keccak256(
            abi.encodePacked(
                bytes1(0xff),
                address(this),
                salt,
                keccak256(bytecode)
            )
        );
        return address(uint160(uint256(hash)));
    }
    
    /**
     * @dev Computes the address where a MultisigUpgradeOperator contract will be deployed using CREATE2
     * @param salt The salt value used for CREATE2 deployment
     * @param upgradeOperator The address of the UpgradeOperator to control
     * @return The predicted contract address
     */
    function computeMultisigUpgradeOperatorAddress(bytes32 salt, address upgradeOperator) public view returns (address) {
        bytes memory bytecode = abi.encodePacked(
            type(MultisigUpgradeOperator).creationCode,
            abi.encode(upgradeOperator)
        );
        bytes32 hash = keccak256(
            abi.encodePacked(
                bytes1(0xff),
                address(this),
                salt,
                keccak256(bytecode)
            )
        );
        return address(uint160(uint256(hash)));
    }
    
    /**
     * @dev Checks if a contract has been deployed at the given address
     * @param contractAddress The address to check
     * @return True if the contract has been deployed
     */
    function isDeployed(address contractAddress) public view returns (bool) {
        return deployedContracts[contractAddress];
    }
} 