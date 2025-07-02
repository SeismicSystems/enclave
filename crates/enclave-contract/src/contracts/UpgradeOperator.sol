// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

/*
 The Upgrade Operator is responsible for defining the 
 configuration to upgrade.

 This is encapsulated in the "rtmr3" reference implementation.
 It's a function of:
     base_image:
     docker compose string of app
*/
contract UpgradeOperator {
    
    // Owner is responsible for initializing
    address owner;
    constructor () {
	owner = msg.sender;
    }

    // Reference RTMR values
    mapping ( bytes32 => bool ) public rtmrs;

    event SetMRTD(bytes rootfs_hash, bytes mrtd, bytes rtmr0, bytes rtmr3, bool status);
    function set_mrtd(bytes memory rootfs_hash,
		      bytes memory mrtd,
		      bytes memory rtmr0,
		      bytes memory rtmr3,
		      bool status) public
    {
	require(msg.sender == owner);
	require(rootfs_hash.length == 32);
	require(mrtd.length == 48);
	require(rtmr0.length == 48);
	require(rtmr3.length == 48);
	rtmrs[keccak256(abi.encodePacked(rootfs_hash,mrtd,rtmr0,rtmr3))] = status;
	emit SetMRTD(rootfs_hash, mrtd, rtmr0, rtmr3, status);
    }
    
    function get_mrtd(bytes memory rootfs_hash,
		      bytes memory mrtd,
		      bytes memory rtmr0,
		      bytes memory rtmr3) public view returns(bool)
    {
	require(rootfs_hash.length == 32);
	require(mrtd.length == 48);
	require(rtmr0.length == 48);
	require(rtmr3.length == 48);
	return rtmrs[keccak256(abi.encodePacked(rootfs_hash,mrtd,rtmr0,rtmr3))];
    }
}