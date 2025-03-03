// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {UpgradeOperator} from "../src/UpgradeOperator.sol";

contract UpgradeOperatorScript is Script {
    UpgradeOperator public upgradeOperator;

    function setUp() public {}

    function run() public {
        vm.startBroadcast(vm.envUint("PRIVATE_KEY")); // Load private key from .env

        upgradeOperator = new UpgradeOperator();

        vm.stopBroadcast();
    }
}

/* 
sforge script script/UpgradeOperator.s.sol:UpgradeOperatorScript \
      --rpc-url $RPC_URL \
      --broadcast
*/