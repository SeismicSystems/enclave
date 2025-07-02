// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./UpgradeOperator.sol";

/**
 * @title MultisigUpgradeOperator
 * @dev Multisig contract that requires 2-of-3 votes to control UpgradeOperator
 * Uses the ANVIL test keys as the three signers
 */
contract MultisigUpgradeOperator {
    
    // The three signers (ANVIL keys)
    address public immutable signer1; // Alice
    address public immutable signer2; // Bob  
    address public immutable signer3; // Charlie
    
    // The UpgradeOperator contract being controlled
    UpgradeOperator public immutable upgradeOperator;
    
    // Nonce counter for proposal uniqueness
    uint256 public proposalNonce;
    
    // Mapping to track votes for each proposal
    mapping(bytes32 => mapping(address => bool)) public votes;
    
    // Mapping to track proposal execution status
    mapping(bytes32 => bool) public executed;
    
    // Event emitted when a proposal is created
    event ProposalCreated(bytes32 indexed proposalId, uint256 nonce, bytes rootfs_hash, bytes mrtd, bytes rtmr0, bytes rtmr3, bool status);
    
    // Event emitted when a vote is cast
    event VoteCast(bytes32 indexed proposalId, address indexed voter, bool approved);
    
    // Event emitted when a proposal is executed
    event ProposalExecuted(bytes32 indexed proposalId);
    
    constructor(address _upgradeOperator) {
        // Set the three signers based on ANVIL keys
        signer1 = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8; // Alice
        signer2 = 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC; // Bob
        signer3 = 0x90F79bf6EB2c4f870365E785982E1f101E93b906; // Charlie
        
        upgradeOperator = UpgradeOperator(_upgradeOperator);
        proposalNonce = 0;
    }
    
    /**
     * @dev Creates a proposal to set MRTD in the UpgradeOperator
     * @param rootfs_hash The rootfs hash (32 bytes)
     * @param mrtd The MRTD value (48 bytes)
     * @param rtmr0 The RTMR0 value (48 bytes)
     * @param rtmr3 The RTMR3 value (48 bytes)
     * @param status The status to set
     * @return proposalId The unique identifier for this proposal
     */
    function createProposal(
        bytes memory rootfs_hash,
        bytes memory mrtd,
        bytes memory rtmr0,
        bytes memory rtmr3,
        bool status
    ) public returns (bytes32 proposalId) {
        require(rootfs_hash.length == 32, "Invalid rootfs_hash length");
        require(mrtd.length == 48, "Invalid mrtd length");
        require(rtmr0.length == 48, "Invalid rtmr0 length");
        require(rtmr3.length == 48, "Invalid rtmr3 length");
        
        // Increment nonce and use it in proposal ID calculation
        proposalNonce++;
        proposalId = keccak256(abi.encodePacked(rootfs_hash, mrtd, rtmr0, rtmr3, status, proposalNonce));
        
        require(!executed[proposalId], "Proposal already executed");
        
        emit ProposalCreated(proposalId, proposalNonce, rootfs_hash, mrtd, rtmr0, rtmr3, status);
        
        return proposalId;
    }
    
    /**
     * @dev Casts a vote on a proposal
     * @param proposalId The proposal to vote on
     * @param approved Whether to approve the proposal
     */
    function vote(bytes32 proposalId, bool approved) public {
        require(msg.sender == signer1 || msg.sender == signer2 || msg.sender == signer3, "Not authorized to vote");
        require(!executed[proposalId], "Proposal already executed");
        require(!votes[proposalId][msg.sender], "Already voted");
        
        votes[proposalId][msg.sender] = approved;
        
        emit VoteCast(proposalId, msg.sender, approved);
    }
    
    /**
     * @dev Executes a proposal if it has enough votes
     * @param rootfs_hash The rootfs hash (32 bytes)
     * @param mrtd The MRTD value (48 bytes)
     * @param rtmr0 The RTMR0 value (48 bytes)
     * @param rtmr3 The RTMR3 value (48 bytes)
     * @param status The status to set
     * @param nonce The nonce used when creating the proposal
     */
    function executeProposal(
        bytes memory rootfs_hash,
        bytes memory mrtd,
        bytes memory rtmr0,
        bytes memory rtmr3,
        bool status,
        uint256 nonce
    ) public {
        bytes32 proposalId = keccak256(abi.encodePacked(rootfs_hash, mrtd, rtmr0, rtmr3, status, nonce));
        
        require(!executed[proposalId], "Proposal already executed");
        
        uint256 approvalCount = 0;
        if (votes[proposalId][signer1]) approvalCount++;
        if (votes[proposalId][signer2]) approvalCount++;
        if (votes[proposalId][signer3]) approvalCount++;
        
        require(approvalCount >= 2, "Insufficient votes");
        
        executed[proposalId] = true;
        
        // Execute the actual set_mrtd call on the UpgradeOperator
        upgradeOperator.set_mrtd(rootfs_hash, mrtd, rtmr0, rtmr3, status);
        
        emit ProposalExecuted(proposalId);
    }
    
    /**
     * @dev Gets the vote count for a proposal
     * @param proposalId The proposal to check
     * @return approvalCount Number of approvals
     * @return totalVotes Total number of votes cast
     */
    function getVoteCount(bytes32 proposalId) public view returns (uint256 approvalCount, uint256 totalVotes) {
        if (votes[proposalId][signer1]) {
            approvalCount++;
            totalVotes++;
        }
        if (votes[proposalId][signer2]) {
            approvalCount++;
            totalVotes++;
        }
        if (votes[proposalId][signer3]) {
            approvalCount++;
            totalVotes++;
        }
        
        return (approvalCount, totalVotes);
    }
    
    /**
     * @dev Checks if a proposal can be executed
     * @param proposalId The proposal to check
     * @return True if the proposal has enough votes to be executed
     */
    function canExecute(bytes32 proposalId) public view returns (bool) {
        if (executed[proposalId]) return false;
        
        uint256 approvalCount = 0;
        if (votes[proposalId][signer1]) approvalCount++;
        if (votes[proposalId][signer2]) approvalCount++;
        if (votes[proposalId][signer3]) approvalCount++;
        
        return approvalCount >= 2;
    }
    
    /**
     * @dev Computes the proposal ID for given parameters and nonce
     * @param rootfs_hash The rootfs hash (32 bytes)
     * @param mrtd The MRTD value (48 bytes)
     * @param rtmr0 The RTMR0 value (48 bytes)
     * @param rtmr3 The RTMR3 value (48 bytes)
     * @param status The status to set
     * @param nonce The nonce to use
     * @return The computed proposal ID
     */
    function computeProposalId(
        bytes memory rootfs_hash,
        bytes memory mrtd,
        bytes memory rtmr0,
        bytes memory rtmr3,
        bool status,
        uint256 nonce
    ) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(rootfs_hash, mrtd, rtmr0, rtmr3, status, nonce));
    }
} 