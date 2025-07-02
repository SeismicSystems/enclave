const { ethers } = require("hardhat");

async function main() {
    console.log("Testing MultisigUpgradeOperator deployment and usage...\n");

    // Get the signers (ANVIL keys)
    const [alice, bob, charlie] = await ethers.getSigners();
    
    console.log("Signers:");
    console.log("Alice:", alice.address);
    console.log("Bob:", bob.address);
    console.log("Charlie:", charlie.address);
    console.log("");

    // Deploy the factory
    const UpgradeOperatorFactory = await ethers.getContractFactory("UpgradeOperatorFactory");
    const factory = await UpgradeOperatorFactory.deploy();
    await factory.deployed();
    console.log("Factory deployed to:", factory.address);

    // Deploy UpgradeOperator and MultisigUpgradeOperator together
    const upgradeOperatorSalt = ethers.utils.id("upgrade-operator-salt");
    const multisigSalt = ethers.utils.id("multisig-salt");
    
    const tx = await factory.deployUpgradeOperatorWithMultisig(upgradeOperatorSalt, multisigSalt);
    const receipt = await tx.wait();
    
    // Get the deployed addresses from events
    const events = receipt.events.filter(e => e.event === "ContractDeployed");
    const upgradeOperatorAddress = events[0].args.contractAddress;
    const multisigAddress = events[1].args.contractAddress;
    
    console.log("UpgradeOperator deployed to:", upgradeOperatorAddress);
    console.log("MultisigUpgradeOperator deployed to:", multisigAddress);
    console.log("");

    // Get the MultisigUpgradeOperator contract
    const MultisigUpgradeOperator = await ethers.getContractFactory("MultisigUpgradeOperator");
    const multisig = MultisigUpgradeOperator.attach(multisigAddress);

    // Test data
    const rootfs_hash = ethers.utils.randomBytes(32);
    const mrtd = ethers.utils.randomBytes(48);
    const rtmr0 = ethers.utils.randomBytes(48);
    const rtmr3 = ethers.utils.randomBytes(48);
    const status = true;

    console.log("Test data:");
    console.log("rootfs_hash:", ethers.utils.hexlify(rootfs_hash));
    console.log("mrtd:", ethers.utils.hexlify(mrtd));
    console.log("rtmr0:", ethers.utils.hexlify(rtmr0));
    console.log("rtmr3:", ethers.utils.hexlify(rtmr3));
    console.log("status:", status);
    console.log("");

    // Create a proposal
    console.log("Creating proposal...");
    const proposalId = await multisig.createProposal(rootfs_hash, mrtd, rtmr0, rtmr3, status);
    console.log("Proposal created with ID:", proposalId);
    console.log("");

    // Alice votes yes
    console.log("Alice voting yes...");
    await multisig.connect(alice).vote(proposalId, true);
    console.log("Alice voted yes");

    // Bob votes yes
    console.log("Bob voting yes...");
    await multisig.connect(bob).vote(proposalId, true);
    console.log("Bob voted yes");
    console.log("");

    // Check vote count
    const [approvalCount, totalVotes] = await multisig.getVoteCount(proposalId);
    console.log("Vote count - Approvals:", approvalCount.toString(), "Total votes:", totalVotes.toString());

    // Check if can execute
    const canExecute = await multisig.canExecute(proposalId);
    console.log("Can execute:", canExecute);
    console.log("");

    // Execute the proposal
    console.log("Executing proposal...");
    await multisig.executeProposal(rootfs_hash, mrtd, rtmr0, rtmr3, status);
    console.log("Proposal executed successfully!");

    // Verify the MRTD was set in the UpgradeOperator
    const UpgradeOperator = await ethers.getContractFactory("UpgradeOperator");
    const upgradeOperator = UpgradeOperator.attach(upgradeOperatorAddress);
    
    const mrtdStatus = await upgradeOperator.get_mrtd(rootfs_hash, mrtd, rtmr0, rtmr3);
    console.log("MRTD status in UpgradeOperator:", mrtdStatus);
    console.log("");

    console.log("Test completed successfully!");
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    }); 