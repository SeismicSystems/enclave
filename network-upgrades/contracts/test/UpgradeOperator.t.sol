// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {UpgradeOperator} from "../src/UpgradeOperator.sol";
import "forge-std/Vm.sol";

contract UpgradeOperatorTest is Test {
    UpgradeOperator public uop;

    Vm.Wallet alice;
    Vm.Wallet bob;
    Vm.Wallet carol;

    function setUp() public {
        vm.prank(vm.addr(uint(keccak256("UpgradeOperator.t.sol"))));
        uop = new UpgradeOperator();

        alice = vm.createWallet("alice");
        bob = vm.createWallet("bob");
    }

    function test_bootstrap() public {

	bytes memory rootfs_hash = hex"b5686a419bbbe59b475ef403083b4cdc22e0d65547aaedf5031c7bc0fd4fac03";
	bytes memory mrtd = hex"7ba9e262ce6979087e34632603f354dd8f8a870f5947d116af8114db6c9d0d74c48bec4280e5b4f4a37025a10905bb29";
	bytes memory rtmr0 = hex"698a1e5764ff07840695fb46c809949cca352e6c9d26fc37dce872402adc071b3b069b0b217c1dcda68cf914253b6842";
	bytes memory rtmr3 = hex"3c30787034cd9aabff0347bc8f08b9f24a0f6ae914bbca0f9aba681e857aa57a7a7cc5b0b67231779cdc345f107707c5";

	assertFalse(uop.get_mrtd(rootfs_hash, mrtd, rtmr0, rtmr3));

        vm.prank(vm.addr(uint(keccak256("UpgradeOperator.t.sol"))));
	uop.set_mrtd(rootfs_hash, mrtd, rtmr0, rtmr3, true);

	assertTrue(uop.get_mrtd(rootfs_hash, mrtd, rtmr0, rtmr3));
    }
    
}