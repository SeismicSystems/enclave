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
    address public constant signer1 = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266; // Alice (0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80)
    address public constant signer2 = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8; // Bob (0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d)
    address public constant signer3 = 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC; // Charlie (0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a)
    
    // The UpgradeOperator contract being controlled
    UpgradeOperator constant public upgradeOperator = UpgradeOperator(0x1000000000000000000000000000000000000001); // Set in seismic-reth genesis
    
    // Nonce counter for proposal uniqueness
    uint256 public proposalNonce;
    
    // Mapping to track votes for each proposal
    mapping(bytes32 => mapping(address => bool)) public votes;
    
    // Mapping to track proposal execution status
    mapping(bytes32 => bool) public executed;
    
    // Event emitted when a proposal is created (version 1)
    event ProposalCreatedV1(bytes32 indexed proposalId, uint256 nonce, bytes mrtd, bytes mrseam, bytes pcr4, bool status);
    
    // Event emitted when a vote is cast
    event VoteCast(bytes32 indexed proposalId, address indexed voter, bool approved);
    
    // Event emitted when a proposal is executed
    event ProposalExecuted(bytes32 indexed proposalId);
    
    // Event emitted when upgrade operator is set
    event UpgradeOperatorSet(address indexed upgradeOperator);
    
    /**
     * @dev Creates a proposal to set defining attributes (version 1) in the UpgradeOperator
     * @param mrtd The MRTD value (48 bytes)
     * @param mrseam The MRSEAM value (48 bytes)
     * @param pcr4 The PCR4 value (32 bytes)
     * @param status The status to set
     * @return proposalId The unique identifier for this proposal
     */
    function createProposalV1(
        bytes memory mrtd,
        bytes memory mrseam,
        bytes memory pcr4,
        bool status
    ) public returns (bytes32 proposalId) {
        require(mrtd.length == 48, "Invalid mrtd length");
        require(mrseam.length == 48, "Invalid mrseam length");
        require(pcr4.length == 32, "Invalid pcr4 length");
        
        // Increment nonce and use it in proposal ID calculation
        proposalNonce++;
        proposalId = computeProposalIdV1(mrtd, mrseam, pcr4, status, proposalNonce);

        require(!executed[proposalId], "Proposal already executed");
        
        emit ProposalCreatedV1(proposalId, proposalNonce, mrtd, mrseam, pcr4, status);
        
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
     * @dev Executes a proposal if it has enough votes (version 1)
     * @param mrtd The MRTD value (48 bytes)
     * @param mrseam The MRSEAM value (48 bytes)
     * @param pcr4 The PCR4 value (32 bytes)
     * @param status The status to set
     * @param nonce The nonce used when creating the proposal
     */
    function executeProposalV1(
        bytes memory mrtd,
        bytes memory mrseam,
        bytes memory pcr4,
        bool status,
        uint256 nonce
    ) public {
        bytes32 proposalId = computeProposalIdV1(mrtd, mrseam, pcr4, status, nonce);
        
        require(!executed[proposalId], "Proposal already executed");
        
        uint256 approvalCount = 0;
        if (votes[proposalId][signer1]) approvalCount++;
        if (votes[proposalId][signer2]) approvalCount++;
        if (votes[proposalId][signer3]) approvalCount++;
        
        require(approvalCount >= 2, "Insufficient votes");
        
        executed[proposalId] = true;
        
        // Execute the actual set_id_status_v1 call on the UpgradeOperator
        upgradeOperator.set_id_status_v1(mrtd, mrseam, pcr4, status);
        
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
     * @dev Computes the proposal ID for given parameters and nonce (version 1)
     * Uses the UpgradeOperator's computeIdV1 method for the base ID calculation
     * @param mrtd The MRTD value (48 bytes)
     * @param mrseam The MRSEAM value (48 bytes)
     * @param pcr4 The PCR4 value (32 bytes)
     * @param status The status to set
     * @param nonce The nonce to use
     * @return The computed proposal ID
     */
    function computeProposalIdV1(
        bytes memory mrtd,
        bytes memory mrseam,
        bytes memory pcr4,
        bool status,
        uint256 nonce
    ) public pure returns (bytes32) {
        // Create the DefiningAttributesV1 struct and use the UpgradeOperator's computeIdV1 method
        UpgradeOperator.DefiningAttributesV1 memory attrs = UpgradeOperator.DefiningAttributesV1(mrtd, mrseam, pcr4);
        
        bytes32 baseId;
        try upgradeOperator.computeIdV1(attrs) returns (bytes32 result) {
            baseId = result;
        } catch {
            revert("upgradeOperator.computeIdV1 failed");
        }

        // Combine with status and nonce for proposal uniqueness
        return keccak256(abi.encodePacked(baseId, status, nonce));
    }
} 