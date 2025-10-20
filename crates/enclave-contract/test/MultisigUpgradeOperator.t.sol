// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../contracts/UpgradeOperator.sol";
import "../contracts/MultisigUpgradeOperator.sol";

contract MultisigUpgradeOperatorTest is Test {
    UpgradeOperatorMock public upgradeOperator;
    MultisigUpgradeOperator public multisig;

    // ANVIL test accounts
    address public signer1 = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
    address public signer2 = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;
    address public signer3 = 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC;
    address public nonSigner = address(0x4);

    // Test data
    UpgradeOperator.Measurements public testMeasurement1;
    UpgradeOperator.Measurements public testMeasurement2;

    event ProposalCreated(
        bytes32 indexed proposalId,
        MultisigUpgradeOperator.ProposalType indexed proposalType,
        string tag,
        uint256 nonce
    );

    event VoteCast(bytes32 indexed proposalId, address indexed voter);

    event ProposalExecuted(
        bytes32 indexed proposalId,
        MultisigUpgradeOperator.ProposalType indexed proposalType
    );

    function setUp() public {
        // Deploy MultisigUpgradeOperator
        multisig = new MultisigUpgradeOperator();

        // Since we can't actually transfer ownership in this test setup,
        // we'll use vm.etch to deploy the UpgradeOperator at the expected address
        // and modify it to accept the multisig as owner

        // For testing purposes, we'll deploy a modified UpgradeOperator
        // that accepts our multisig as the owner
        UpgradeOperatorMock mockUpgradeOperator = new UpgradeOperatorMock(
            address(multisig)
        );
        vm.etch(
            address(0x1000000000000000000000000000000000000001),
            address(mockUpgradeOperator).code
        );

        upgradeOperator = UpgradeOperatorMock(
            0x1000000000000000000000000000000000000001
        );

        // Setup test measurements
        testMeasurement1.tag = "AzureV1";
        testMeasurement1
            .mrtd = hex"111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";
        testMeasurement1
            .mrseam = hex"222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222";
        testMeasurement1.registrar_slots = new uint8[](2);
        testMeasurement1.registrar_slots[0] = 4;
        testMeasurement1.registrar_slots[1] = 5;
        testMeasurement1.registrar_values = new bytes[](2);
        testMeasurement1.registrar_values[
            0
        ] = hex"33333333333333333333333333333333333333333333333333333333";
        testMeasurement1.registrar_values[
            1
        ] = hex"44444444444444444444444444444444444444444444444444444444";

        testMeasurement2.tag = "AWSV1";
        testMeasurement2
            .mrtd = hex"555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555";
        testMeasurement2
            .mrseam = hex"666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666";
        testMeasurement2.registrar_slots = new uint8[](1);
        testMeasurement2.registrar_slots[0] = 3;
        testMeasurement2.registrar_values = new bytes[](1);
        testMeasurement2.registrar_values[
            0
        ] = hex"77777777777777777777777777777777777777777777777777777777";
    }

    // Test proposal creation for adding measurements
    function testProposeAddMeasurements() public {
        vm.prank(signer1);

        bytes32 proposalId = multisig.proposeAddMeasurements(testMeasurement1);

        // Check proposal was created
        (
            MultisigUpgradeOperator.ProposalType proposalType,
            string memory tag,
            bool executed,
            uint256 voteCount
        ) = multisig.getProposalInfo(proposalId);

        assertEq(
            uint(proposalType),
            uint(MultisigUpgradeOperator.ProposalType.ADD_MEASUREMENTS)
        );
        assertEq(tag, "AzureV1");
        assertFalse(executed);
        assertEq(voteCount, 1); // Auto-voted by proposer
    }

    // Test non-signer cannot create proposals
    function testNonSignerCannotPropose() public {
        vm.prank(nonSigner);
        vm.expectRevert("Not authorized");
        multisig.proposeAddMeasurements(testMeasurement1);
    }

    // Test voting on proposal
    function testVoting() public {
        vm.prank(signer1);
        bytes32 proposalId = multisig.proposeAddMeasurements(testMeasurement1);

        // Check initial vote count
        (uint256 voteCount, , , , ) = multisig.getVoteStatus(proposalId);
        assertEq(voteCount, 1);

        // Second signer votes
        vm.prank(signer2);
        vm.expectEmit(true, true, false, true);
        emit VoteCast(proposalId, signer2);
        multisig.vote(proposalId);

        // Check vote count increased
        (voteCount, , , , ) = multisig.getVoteStatus(proposalId);
        assertEq(voteCount, 2);
    }

    // Test double voting fails
    function testDoubleVoteFails() public {
        vm.prank(signer1);
        bytes32 proposalId = multisig.proposeAddMeasurements(testMeasurement1);

        vm.prank(signer1);
        vm.expectRevert("Already voted");
        multisig.vote(proposalId);
    }

    // Test manual execution
    function testManualExecution() public {
        vm.prank(signer1);
        bytes32 proposalId = multisig.proposeAddMeasurements(testMeasurement1);

        vm.prank(signer2);
        multisig.vote(proposalId);

        // Anyone can execute once threshold is met
        vm.prank(nonSigner);
        multisig.executeProposal(proposalId);

        // Check proposal is executed
        (, , bool executed, ) = multisig.getProposalInfo(proposalId);
        assertTrue(executed);
    }

    // Test cannot execute without enough votes
    function testCannotExecuteWithoutVotes() public {
        vm.prank(signer1);
        bytes32 proposalId = multisig.proposeAddMeasurements(testMeasurement1);

        vm.expectRevert("Insufficient votes");
        multisig.executeProposal(proposalId);
    }

    // Test deprecate measurements proposal
    function testProposeDeprecateMeasurements() public {
        // First add a measurement via multisig
        vm.prank(signer1);
        bytes32 addProposalId = multisig.proposeAddMeasurements(
            testMeasurement1
        );
        vm.prank(signer2);
        multisig.vote(addProposalId);
        multisig.executeProposal(addProposalId);

        assertTrue(upgradeOperator.isAccepted("AzureV1"));

        // Now propose to deprecate it
        vm.prank(signer1);
        bytes32 deprecateProposalId = multisig.proposeDeprecateMeasurements(
            "AzureV1"
        );

        // Vote to execute
        vm.prank(signer3);
        multisig.vote(deprecateProposalId);
        multisig.executeProposal(deprecateProposalId);

        // Check it's deprecated
        assertFalse(upgradeOperator.isAccepted("AzureV1"));
        assertTrue(upgradeOperator.isDeprecated("AzureV1"));
    }

    // Test reinstate measurements proposal
    function testProposeReinstateMeasurements() public {
        // Add, then deprecate a measurement
        vm.prank(signer1);
        bytes32 addProposalId = multisig.proposeAddMeasurements(
            testMeasurement1
        );
        vm.prank(signer2);
        multisig.vote(addProposalId);
        multisig.executeProposal(addProposalId);

        vm.prank(signer1);
        bytes32 deprecateProposalId = multisig.proposeDeprecateMeasurements(
            "AzureV1"
        );
        vm.prank(signer2);
        multisig.vote(deprecateProposalId);
        multisig.executeProposal(deprecateProposalId);
        assertFalse(upgradeOperator.isAccepted("AzureV1"));
        assertTrue(upgradeOperator.isDeprecated("AzureV1"));

        // Now propose to reinstate
        vm.prank(signer1);
        bytes32 reinstateProposalId = multisig.proposeReinstateMeasurements(
            "AzureV1"
        );
        vm.prank(signer3);
        multisig.vote(reinstateProposalId);
        multisig.executeProposal(reinstateProposalId);

        // Check it's reinstated
        assertTrue(upgradeOperator.isAccepted("AzureV1"));
        assertFalse(upgradeOperator.isDeprecated("AzureV1"));
    }

    // Test get vote status
    function testGetVoteStatus() public {
        vm.prank(signer1);
        bytes32 proposalId = multisig.proposeAddMeasurements(testMeasurement1);

        (
            uint256 voteCount,
            bool hasVoted1,
            bool hasVoted2,
            bool hasVoted3,
            bool canExecute
        ) = multisig.getVoteStatus(proposalId);

        assertEq(voteCount, 1);
        assertTrue(hasVoted1);
        assertFalse(hasVoted2);
        assertFalse(hasVoted3);
        assertFalse(canExecute);

        vm.prank(signer2);
        multisig.vote(proposalId);

        (voteCount, hasVoted1, hasVoted2, hasVoted3, canExecute) = multisig
            .getVoteStatus(proposalId);

        assertEq(voteCount, 2);
        assertTrue(hasVoted1);
        assertTrue(hasVoted2);
        assertFalse(hasVoted3);
        assertTrue(canExecute);
    }

    // Test complete multisig workflow
    function testCompleteMultisigWorkflow() public {
        // Signer1 proposes to add Azure measurements
        vm.prank(signer1);
        bytes32 proposal1 = multisig.proposeAddMeasurements(testMeasurement1);
        // Signer2 votes, triggering execution
        vm.prank(signer2);
        multisig.vote(proposal1);
        multisig.executeProposal(proposal1);
        assertTrue(upgradeOperator.isAccepted("AzureV1"));

        // Signer2 proposes to add AWS measurements
        vm.prank(signer2);
        bytes32 proposal2 = multisig.proposeAddMeasurements(testMeasurement2);

        // Signer3 votes allowing enough votes for execution
        vm.prank(signer3);
        multisig.vote(proposal2);

        //  execute
        multisig.executeProposal(proposal2);
        assertTrue(upgradeOperator.isAccepted("AWSV1"));

        assertEq(upgradeOperator.getAcceptedCount(), 2);

        // Signer1 proposes to deprecate Azure
        vm.prank(signer1);
        bytes32 proposal3 = multisig.proposeDeprecateMeasurements("AzureV1");

        // Signer2 votes
        vm.prank(signer2);
        multisig.vote(proposal3);
        multisig.executeProposal(proposal3);

        assertFalse(upgradeOperator.isAccepted("AzureV1"));
        assertTrue(upgradeOperator.isDeprecated("AzureV1"));
        assertEq(upgradeOperator.getAcceptedCount(), 1);

        // Signer3 proposes to reinstate Azure
        vm.prank(signer3);
        bytes32 proposal4 = multisig.proposeReinstateMeasurements("AzureV1");

        // Signer1 votes
        vm.prank(signer1);
        multisig.vote(proposal4);
        multisig.executeProposal(proposal4);

        assertTrue(upgradeOperator.isAccepted("AzureV1"));
        assertFalse(upgradeOperator.isDeprecated("AzureV1"));
        assertEq(upgradeOperator.getAcceptedCount(), 2);
    }

    // Test proposal with invalid measurements fails
    function testInvalidMeasurementsFails() public {
        UpgradeOperator.Measurements memory invalidMeasurement;

        // Empty tag
        invalidMeasurement = testMeasurement1;
        invalidMeasurement.tag = "";
        vm.prank(signer1);
        vm.expectRevert("Tag cannot be empty");
        multisig.proposeAddMeasurements(invalidMeasurement);

        // Empty MRTD
        invalidMeasurement = testMeasurement1;
        invalidMeasurement.mrtd = "";
        vm.prank(signer1);
        vm.expectRevert("MRTD cannot be empty");
        multisig.proposeAddMeasurements(invalidMeasurement);

        // Mismatched arrays
        invalidMeasurement = testMeasurement1;
        uint8[] memory slots = new uint8[](3);
        slots[0] = 1;
        slots[1] = 2;
        slots[2] = 3;
        invalidMeasurement.registrar_slots = slots;
        vm.prank(signer1);
        vm.expectRevert("Registrar arrays length mismatch");
        multisig.proposeAddMeasurements(invalidMeasurement);
    }

    // Test get proposal measurements
    function testGetProposalMeasurements() public {
        vm.prank(signer1);
        bytes32 proposalId = multisig.proposeAddMeasurements(testMeasurement1);

        UpgradeOperator.Measurements memory retrieved = multisig
            .getProposalMeasurements(proposalId);

        assertEq(retrieved.tag, testMeasurement1.tag);
        assertEq(retrieved.mrtd, testMeasurement1.mrtd);
        assertEq(retrieved.mrseam, testMeasurement1.mrseam);
        assertEq(retrieved.registrar_slots.length, 2);
        assertEq(retrieved.registrar_values.length, 2);
    }

    // Test cannot get measurements for non-add proposals
    function testCannotGetMeasurementsForDeprecateProposal() public {
        vm.prank(signer1);
        bytes32 proposalId = multisig.proposeDeprecateMeasurements("AzureV1");

        vm.expectRevert("Not an add measurements proposal");
        multisig.getProposalMeasurements(proposalId);
    }
}

// Mock UpgradeOperator for testing that accepts a different owner
contract UpgradeOperatorMock is UpgradeOperator {
    address public immutable testOwner;

    constructor(address _testOwner) {
        testOwner = _testOwner;
    }

    modifier onlyNetworkMultisig() override {
        require(msg.sender == testOwner, "Ownable-- caller is not the owner");
        _;
    }
}
