// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

/*
 The Upgrade Operator is responsible for defining the 
 configuration to upgrade.
*/
contract UpgradeOperator {
    
    struct DefiningAttributesV1 {
        bytes mrtd;
        bytes mrseam;
        bytes pcr4;
    }

    struct DefiningAttributesV2 {
        bytes mrtd;
        bytes mrseam;
        bytes pcr4;
        bytes pcr7;
    }

    address public owner;
    mapping(bytes32 => bool) public attributes;

    event SetDefiningAttributesV1(bytes mrtd, bytes mrseam, bytes pcr4, bool status);
    event SetDefiningAttributesV2(bytes mrtd, bytes mrseam, bytes pcr4, bytes pcr7, bool status);

    constructor(address _owner) {
        owner = _owner;
    }

    /**
     * @dev Sets the status for a set of defining attributes (version 1)
     */
    function set_id_status_v1(bytes memory mrtd, bytes memory mrseam, bytes memory pcr4, bool status) public {
        require(msg.sender == owner);
        require(mrtd.length == 48 && mrseam.length == 48 && pcr4.length == 48);

        DefiningAttributesV1 memory attrs = DefiningAttributesV1(mrtd, mrseam, pcr4);
        bytes32 id = computeIdV1(attrs);
        attributes[id] = status;
        emit SetDefiningAttributesV1(mrtd, mrseam, pcr4, status);
    }

    /**
     * @dev Gets the status of a set of defining attributes (version 1)
     */
    function get_id_status_v1(bytes memory mrtd, bytes memory mrseam, bytes memory pcr4) public view returns (bool) {
        require(mrtd.length == 48 && mrseam.length == 48 && pcr4.length == 48);

        DefiningAttributesV1 memory attrs = DefiningAttributesV1(mrtd, mrseam, pcr4);
        bytes32 id = computeIdV1(attrs);
        return attributes[id];
    }

    /**
     * @dev Computes the ID for a set of defining attributes (version 1)
     */
    function computeIdV1(DefiningAttributesV1 memory attrs) public pure returns (bytes32) {
        return keccak256(abi.encode(attrs));
    }

    /**
     * @dev Computes the ID for a set of defining attributes (version 2)
     */
    function computeIdV2(DefiningAttributesV2 memory attrs) public pure returns (bytes32) {
        return keccak256(abi.encode(attrs));
    }
}