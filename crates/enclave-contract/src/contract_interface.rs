//! Contract interface definitions and types

use alloy::{
    primitives::{address, Address, Bytes},
    providers::ProviderBuilder,
    sol,
};
use anyhow::Result;
use std::sync::Arc;

// Contract address
const OPERATOR_ADDR: Address = address!("0x5FbDB2315678afecb367f032d93F642f64180aa3");

// Generate contract bindings for the factory
sol! {
    #[sol(rpc)]
    interface UpgradeOperatorFactory {
        function deployUpgradeOperator(bytes32 salt) external returns (address);
        function deployUpgradeOperatorWithOwner(bytes32 salt, address owner) external returns (address);
        function deployMultisigUpgradeOperator(bytes32 salt, address upgradeOperator) external returns (address);
        function deployUpgradeOperatorWithMultisig(bytes32 upgradeOperatorSalt, bytes32 multisigSalt) external returns (address, address);
        function computeUpgradeOperatorAddress(bytes32 salt) external view returns (address);
        function computeUpgradeOperatorAddressWithOwner(bytes32 salt, address owner) external view returns (address);
        function computeMultisigUpgradeOperatorAddress(bytes32 salt, address upgradeOperator) external view returns (address);
        function isDeployed(address contractAddress) external view returns (bool);
    }
}

// Generate contract bindings for the upgrade operator
sol! {
    #[sol(rpc)]
    interface UpgradeOperator {
        function set_id_status_v1(bytes mrtd, bytes mrseam, bytes pcr4, bool status) external;
        function get_id_status_v1(bytes mrtd, bytes mrseam, bytes pcr4) external view returns (bool);
        function computeIdV1(bytes mrtd, bytes mrseam, bytes pcr4) external pure returns (bytes32);
        function owner() external view returns (address);
    }
}

// Generate contract bindings for the multisig contract
sol! {
    #[sol(rpc)]
    interface MultisigUpgradeOperator {
        function createProposalV1(bytes mrtd, bytes mrseam, bytes pcr4, bool status) external returns (bytes32);
        function vote(bytes32 proposalId, bool approved) external;
        function executeProposalV1(bytes mrtd, bytes mrseam, bytes pcr4, bool status, uint256 nonce) external;
        function getVoteCount(bytes32 proposalId) external view returns (uint256 approvalCount, uint256 totalVotes);
        function canExecute(bytes32 proposalId) external view returns (bool);
        function computeProposalIdV1(bytes mrtd, bytes mrseam, bytes pcr4, bool status, uint256 nonce) external view returns (bytes32);
        function proposalNonce() external view returns (uint256);
        function signer1() external view returns (address);
        function signer2() external view returns (address);
        function signer3() external view returns (address);
        function upgradeOperator() external view returns (address);
        function setUpgradeOperator(address _upgradeOperator) external;
        function factory() external view returns (address);
    }
}

/// Checks if a specified configuration is an approved upgrade (version 1).
///
/// This function makes a view call to the `UpgradeOperator` contract on a local node
/// to invoke the `get_id_status_v1` function. The function evaluates whether the given configuration
/// has been registered as approved on-chain.
pub async fn provider_check_proposal_status_v1(
    mrtd: Bytes,
    mrseam: Bytes,
    pcr4: Bytes,
) -> Result<bool, anyhow::Error> {
    // Set up the provider to connect to the local node
    let provider = ProviderBuilder::new().connect_http("http://localhost:8545".parse()?);

    // Instantiate the contract
    let contract = UpgradeOperator::new(OPERATOR_ADDR, Arc::new(provider));
    let builder = contract.get_id_status_v1(mrtd, mrseam, pcr4);
    let is_valid = builder
        .call()
        .await
        .map_err(|e| anyhow::anyhow!("Call to get_id_status_v1 failed: {:?}", e))?;

    Ok(is_valid)
}

/// Legacy function for backward compatibility - now calls the new V1 function
#[deprecated(since = "1.0.0", note = "Use provider_check_proposal_status_v1 instead")]
pub async fn provider_check_mrtd(
    _rootfs_hash: Bytes,
    mrtd: Bytes,
    _rtmr0: Bytes,
    _rtmr3: Bytes,
) -> Result<bool, anyhow::Error> {
    // For backward compatibility, we'll use the new V1 function with the mrtd parameter
    // and create dummy values for the new required parameters
    let mrseam = Bytes::from(vec![0x00; 48]); // Default value
    let pcr4 = Bytes::from(vec![0x00; 48]);   // Default value
    
    provider_check_proposal_status_v1(mrtd, mrseam, pcr4).await
}