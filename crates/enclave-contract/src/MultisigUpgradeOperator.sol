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
    address public constant signer1 =
        0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266; // Alice (0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80)
    address public constant signer2 =
        0x70997970C51812dc3A010C7d01b50e0d17dc79C8; // Bob (0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d)
    address public constant signer3 =
        0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC; // Charlie (0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a)

    // The UpgradeOperator contract being controlled
    UpgradeOperator public immutable upgradeOperator =
        UpgradeOperator(0x1000000000000000000000000000000000000001); // Set in seismic-reth genesis

    // Nonce counter for proposal uniqueness
    uint256 public proposalNonce;

    // Enum for proposal types
    enum ProposalType {
        ADD_MEASUREMENTS,
        DEPRECATE_MEASUREMENTS,
        REINSTATE_MEASUREMENTS
    }

    // Proposal struct
    struct Proposal {
        ProposalType proposalType;
        bytes32 tagHash;
        UpgradeOperator.Measurements measurements;
        bool executed;
        uint256 voteCount;
        mapping(address => bool) hasVoted;
    }

    // Mapping to track proposals
    mapping(bytes32 => Proposal) public proposals;

    // Events
    event ProposalCreated(
        bytes32 indexed proposalId,
        ProposalType indexed proposalType,
        string tag,
        uint256 nonce
    );

    event VoteCast(bytes32 indexed proposalId, address indexed voter);

    event ProposalExecuted(
        bytes32 indexed proposalId,
        ProposalType indexed proposalType
    );

    modifier onlySigner() {
        require(
            msg.sender == signer1 ||
                msg.sender == signer2 ||
                msg.sender == signer3,
            "Not authorized"
        );
        _;
    }

    /**
     * @dev Creates a proposal to add new measurements
     * @param measurements The measurements to add
     * @return proposalId The unique identifier for this proposal
     */
    function proposeAddMeasurements(
        UpgradeOperator.Measurements calldata measurements
    ) external onlySigner returns (bytes32 proposalId) {
        // Validate inputs
        require(bytes(measurements.tag).length > 0, "Tag cannot be empty");
        require(measurements.mrtd.length > 0, "MRTD cannot be empty");
        require(measurements.mrseam.length > 0, "MRSEAM cannot be empty");
        require(
            measurements.registrar_slots.length ==
                measurements.registrar_values.length,
            "Registrar arrays length mismatch"
        );

        proposalNonce++;
        proposalId = keccak256(
            abi.encodePacked(
                ProposalType.ADD_MEASUREMENTS,
                measurements.tag,
                measurements.mrtd,
                measurements.mrseam,
                proposalNonce
            )
        );

        Proposal storage proposal = proposals[proposalId];
        require(!proposal.executed, "Proposal already exists");

        proposal.proposalType = ProposalType.ADD_MEASUREMENTS;
        proposal.tagHash = keccak256(abi.encodePacked(measurements.tag));
        proposal.measurements = measurements;

        emit ProposalCreated(
            proposalId,
            ProposalType.ADD_MEASUREMENTS,
            measurements.tag,
            proposalNonce
        );

        // Auto-vote for proposer
        _vote(proposalId);

        return proposalId;
    }

    /**
     * @dev Creates a proposal to deprecate measurements
     * @param tag The tag of measurements to deprecate
     * @return proposalId The unique identifier for this proposal
     */
    function proposeDeprecateMeasurements(
        string calldata tag
    ) external onlySigner returns (bytes32 proposalId) {
        require(bytes(tag).length > 0, "Tag cannot be empty");

        proposalNonce++;
        proposalId = keccak256(
            abi.encodePacked(
                ProposalType.DEPRECATE_MEASUREMENTS,
                tag,
                proposalNonce
            )
        );

        Proposal storage proposal = proposals[proposalId];
        require(!proposal.executed, "Proposal already exists");

        proposal.proposalType = ProposalType.DEPRECATE_MEASUREMENTS;
        proposal.tagHash = keccak256(abi.encodePacked(tag));
        // Store tag in measurements.tag for execution
        proposal.measurements.tag = tag;

        emit ProposalCreated(
            proposalId,
            ProposalType.DEPRECATE_MEASUREMENTS,
            tag,
            proposalNonce
        );

        // Auto-vote for proposer
        _vote(proposalId);

        return proposalId;
    }

    /**
     * @dev Creates a proposal to reinstate measurements
     * @param tag The tag of measurements to reinstate
     * @return proposalId The unique identifier for this proposal
     */
    function proposeReinstateMeasurements(
        string calldata tag
    ) external onlySigner returns (bytes32 proposalId) {
        require(bytes(tag).length > 0, "Tag cannot be empty");

        proposalNonce++;
        proposalId = keccak256(
            abi.encodePacked(
                ProposalType.REINSTATE_MEASUREMENTS,
                tag,
                proposalNonce
            )
        );

        Proposal storage proposal = proposals[proposalId];
        require(!proposal.executed, "Proposal already exists");

        proposal.proposalType = ProposalType.REINSTATE_MEASUREMENTS;
        proposal.tagHash = keccak256(abi.encodePacked(tag));
        // Store tag in measurements.tag for execution
        proposal.measurements.tag = tag;

        emit ProposalCreated(
            proposalId,
            ProposalType.REINSTATE_MEASUREMENTS,
            tag,
            proposalNonce
        );

        // Auto-vote for proposer
        _vote(proposalId);

        return proposalId;
    }

    /**
     * @dev Vote on a proposal
     * @param proposalId The proposal to vote on
     */
    function vote(bytes32 proposalId) external onlySigner {
        _vote(proposalId);
    }

    /**
     * @dev Internal vote logic
     */
    function _vote(bytes32 proposalId) internal {
        Proposal storage proposal = proposals[proposalId];

        require(!proposal.executed, "Proposal already executed");
        require(!proposal.hasVoted[msg.sender], "Already voted");

        proposal.hasVoted[msg.sender] = true;
        proposal.voteCount++;

        emit VoteCast(proposalId, msg.sender);

        // todo we probably dont want auto execute
        // Auto-execute if threshold reached
        // if (proposal.voteCount >= 2) {
        //     _executeProposal(proposalId);
        // }
    }

    /**
     * @dev Execute a proposal that has enough votes
     * @param proposalId The proposal to execute
     */
    function executeProposal(bytes32 proposalId) external {
        Proposal storage proposal = proposals[proposalId];

        require(!proposal.executed, "Proposal already executed");
        require(proposal.voteCount >= 2, "Insufficient votes");
        _executeProposal(proposalId);
    }

    /**
     * @dev Internal execution logic
     */
    function _executeProposal(bytes32 proposalId) internal {
        Proposal storage proposal = proposals[proposalId];

        proposal.executed = true;

        if (proposal.proposalType == ProposalType.ADD_MEASUREMENTS) {
            upgradeOperator.addAcceptedMeasurements(proposal.measurements);
        } else if (
            proposal.proposalType == ProposalType.DEPRECATE_MEASUREMENTS
        ) {
            upgradeOperator.deprecateMeasurements(proposal.measurements.tag);
        } else if (
            proposal.proposalType == ProposalType.REINSTATE_MEASUREMENTS
        ) {
            upgradeOperator.reinstateMeasurement(proposal.measurements.tag);
        }

        emit ProposalExecuted(proposalId, proposal.proposalType);
    }

    /**
     * @dev Get vote status for a proposal
     * @param proposalId The proposal to check
     * @return voteCount Number of votes
     * @return hasVoted1 Whether signer1 voted
     * @return hasVoted2 Whether signer2 voted
     * @return hasVoted3 Whether signer3 voted
     * @return canExecute Whether proposal can be executed
     */
    function getVoteStatus(
        bytes32 proposalId
    )
        external
        view
        returns (
            uint256 voteCount,
            bool hasVoted1,
            bool hasVoted2,
            bool hasVoted3,
            bool canExecute
        )
    {
        Proposal storage proposal = proposals[proposalId];

        voteCount = proposal.voteCount;
        hasVoted1 = proposal.hasVoted[signer1];
        hasVoted2 = proposal.hasVoted[signer2];
        hasVoted3 = proposal.hasVoted[signer3];
        canExecute = !proposal.executed && proposal.voteCount >= 2;
    }

    /**
     * @dev Get proposal details
     * @param proposalId The proposal to query
     * @return proposalType The type of proposal
     * @return tag The measurement tag
     * @return executed Whether the proposal has been executed
     * @return voteCount Number of votes
     */
    function getProposalInfo(
        bytes32 proposalId
    )
        external
        view
        returns (
            ProposalType proposalType,
            string memory tag,
            bool executed,
            uint256 voteCount
        )
    {
        Proposal storage proposal = proposals[proposalId];

        return (
            proposal.proposalType,
            proposal.measurements.tag,
            proposal.executed,
            proposal.voteCount
        );
    }

    /**
     * @dev Get full measurement details for an add proposal
     * @param proposalId The proposal to query
     * @return measurements The full measurements struct
     */
    function getProposalMeasurements(
        bytes32 proposalId
    ) external view returns (UpgradeOperator.Measurements memory) {
        require(
            proposals[proposalId].proposalType == ProposalType.ADD_MEASUREMENTS,
            "Not an add measurements proposal"
        );
        return proposals[proposalId].measurements;
    }
}
