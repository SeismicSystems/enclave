// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./UpgradeOperator.sol";

/**
 * @title UpgradeOperatorFactory
 * @dev Factory contract for deploying UpgradeOperator contracts using CREATE2
 * This allows for predictable contract addresses based on salt values
 */
contract UpgradeOperatorFactory {
    
    // Mapping to track deployed contracts
    mapping(address => bool) public deployedContracts;
    
    // Event emitted when a new contract is deployed
    event ContractDeployed(address indexed contractAddress, bytes32 indexed salt);
    
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
        
        emit ContractDeployed(contractAddress, salt);
        
        return contractAddress;
    }
    
    /**
     * @dev Computes the address where a contract will be deployed using CREATE2
     * @param salt The salt value used for CREATE2 deployment
     * @return The predicted contract address
     */
    function computeAddress(bytes32 salt) public view returns (address) {
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
     * @dev Checks if a contract has been deployed at the given address
     * @param contractAddress The address to check
     * @return True if the contract has been deployed
     */
    function isDeployed(address contractAddress) public view returns (bool) {
        return deployedContracts[contractAddress];
    }
} 