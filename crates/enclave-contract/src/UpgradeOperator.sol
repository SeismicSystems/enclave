// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract UpgradeOperator {
    struct Measurements {
        string tag;
        bytes mrtd;
        bytes mrseam;
        uint8[] registrar_slots;
        bytes[] registrar_values;
    }

    mapping(bytes32 => Measurements) public acceptedMeasurements;
    mapping(bytes32 => Measurements) public deprecatedMeasurements;

    // Keep track of all tags for enumeration if needed
    bytes32[] public acceptedTags;
    bytes32[] public deprecatedTags;

    // Track if a tag exists to prevent duplicates
    mapping(bytes32 => bool) public tagExists;

    address public constant OWNER = 0x1000000000000000000000000000000000000002;

    event MeasurementAdded(string indexed tag, bytes32 indexed tagHash);
    event MeasurementDeprecated(string indexed tag, bytes32 indexed tagHash);

    modifier onlyNetworkMultisig() virtual {
        require(msg.sender == OWNER, "Ownable: caller is not the owner");
        _;
    }

    /**
     * @dev Add a set of measurements the network allows
     * @param measurements The measurements to add
     */
    function addAcceptedMeasurements(
        Measurements calldata measurements
    ) external onlyNetworkMultisig {
        bytes32 tagHash = keccak256(abi.encodePacked(measurements.tag));

        // Check uniqueness
        require(!tagExists[tagHash], "Measurement tag already exists");

        // Validate inputs TODO: assert actual length these measurements should be
        require(bytes(measurements.tag).length > 0, "Tag cannot be empty");
        require(measurements.mrtd.length > 0, "MRTD cannot be empty");
        require(measurements.mrseam.length > 0, "MRSEAM cannot be empty");
        require(
            measurements.registrar_slots.length ==
                measurements.registrar_values.length,
            "Registrar arrays length mismatch"
        );

        // Store the measurement
        acceptedMeasurements[tagHash] = measurements;
        acceptedTags.push(tagHash);
        tagExists[tagHash] = true;

        emit MeasurementAdded(measurements.tag, tagHash);
    }
    /**
     * @dev accept a currently deprecated set of measurements
     * @param tag The tag of the measurement to reinstate
     */
    function reinstateMeasurement(
        string calldata tag
    ) external onlyNetworkMultisig {
        bytes32 tagHash = keccak256(abi.encodePacked(tag));

        // Check if measurement exists in accepted
        require(
            bytes(deprecatedMeasurements[tagHash].tag).length > 0,
            "No deprecated measurement with that tag"
        );

        // Move from deprecated to accepted
        Measurements memory measurement = deprecatedMeasurements[tagHash];
        acceptedMeasurements[tagHash] = measurement;
        acceptedTags.push(tagHash);

        // Remove from deprecated
        delete deprecatedMeasurements[tagHash];
        _removeFromArray(deprecatedTags, tagHash);

        emit MeasurementAdded(tag, tagHash);
    }

    /**
     * @dev Deprecate a currently allowed set of measurements
     * @param tag The tag of the measurement to deprecate
     */
    function deprecateMeasurements(
        string calldata tag
    ) external onlyNetworkMultisig {
        bytes32 tagHash = keccak256(abi.encodePacked(tag));

        // Check if measurement exists in accepted
        require(
            bytes(acceptedMeasurements[tagHash].tag).length > 0,
            "No accepted measurement with that tag"
        );

        // Move from accepted to deprecated
        Measurements memory measurement = acceptedMeasurements[tagHash];
        deprecatedMeasurements[tagHash] = measurement;
        deprecatedTags.push(tagHash);

        // Remove from accepted
        delete acceptedMeasurements[tagHash];
        _removeFromArray(acceptedTags, tagHash);

        emit MeasurementDeprecated(tag, tagHash);
    }

    /**
     * @dev Check if measurements are accepted
     * @param tag The tag to check
     */
    function isAccepted(string calldata tag) external view returns (bool) {
        bytes32 tagHash = keccak256(abi.encodePacked(tag));
        return bytes(acceptedMeasurements[tagHash].tag).length > 0;
    }

    /**
     * @dev Check if measurements are accepted
     * @param tag The tag to check
     */
    function isDeprecated(string calldata tag) external view returns (bool) {
        bytes32 tagHash = keccak256(abi.encodePacked(tag));
        return bytes(deprecatedMeasurements[tagHash].tag).length > 0;
    }

    /**
     * @dev Get accepted measurement by tag
     */
    function getAcceptedMeasurement(
        string calldata tag
    ) external view returns (Measurements memory) {
        bytes32 tagHash = keccak256(abi.encodePacked(tag));
        require(
            bytes(acceptedMeasurements[tagHash].tag).length > 0,
            "Measurement not found"
        );
        return acceptedMeasurements[tagHash];
    }

    /**
     * @dev Get count of accepted measurements
     */
    function getAcceptedCount() external view returns (uint256) {
        return acceptedTags.length;
    }

    /**
     * @dev Helper to remove element from array
     */
    function _removeFromArray(
        bytes32[] storage array,
        bytes32 element
    ) private {
        for (uint256 i = 0; i < array.length; i++) {
            if (array[i] == element) {
                array[i] = array[array.length - 1];
                array.pop();
                break;
            }
        }
    }
}
