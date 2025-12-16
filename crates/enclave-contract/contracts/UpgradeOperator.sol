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
    bool public initialIsDeprecated = false;

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

        bytes32 measurementHash = _getMeasurementHash(measurements);

        // Store the measurement
        acceptedMeasurements[measurementHash] = measurements;
        acceptedTags.push(measurementHash);
        tagExists[tagHash] = true;

        emit MeasurementAdded(measurements.tag, measurementHash);
    }
    /**
     * @dev accept a currently deprecated set of measurements
     * @param m the measurement to reinstate
     */
    function reinstateMeasurement(
        Measurements calldata m
    ) external onlyNetworkMultisig {
        bytes32 tagHash = keccak256(abi.encodePacked(m.tag));

        bytes32 measurementHash = _getMeasurementHash(m);

        // Check if measurement exists in deprecated
        require(
            keccak256(
                abi.encodePacked(deprecatedMeasurements[measurementHash].tag)
            ) == tagHash,
            "No deprecated measurement with that tag or hash"
        );

        // Move from deprecated to accepted
        Measurements memory measurement = deprecatedMeasurements[
            measurementHash
        ];
        acceptedMeasurements[measurementHash] = measurement;
        acceptedTags.push(measurementHash);

        // Remove from deprecated
        delete deprecatedMeasurements[measurementHash];
        _removeFromArray(deprecatedTags, measurementHash);

        emit MeasurementAdded(m.tag, measurementHash);
    }

    /**
     * @dev Deprecate a currently allowed set of measurements
     * @param m the measurement to deprecate
     */
    function deprecateMeasurements(
        Measurements calldata m
    ) external onlyNetworkMultisig {
        bytes32 tagHash = keccak256(abi.encodePacked(m.tag));
        bytes32 measurementHash = _getMeasurementHash(m);
        // Check if measurement exists in accepted
        require(
            keccak256(
                abi.encodePacked(acceptedMeasurements[measurementHash].tag)
            ) == tagHash,
            "No deprecated measurement with that tag or hash"
        );

        // Move from accepted to deprecated
        Measurements memory measurement = acceptedMeasurements[measurementHash];
        deprecatedMeasurements[measurementHash] = measurement;
        deprecatedTags.push(measurementHash);

        // Remove from accepted
        delete acceptedMeasurements[measurementHash];
        _removeFromArray(acceptedTags, measurementHash);

        emit MeasurementDeprecated(m.tag, measurementHash);
    }

    /**
     * @dev Check if measurements are accepted
     * @param measurementHash Hash of the measurements to check
     */
    function isAccepted(bytes32 measurementHash) external view returns (bool) {
        if (
            !initialIsDeprecated &&
            measurementHash == _getMeasurementHash(getInitialMeasurements())
        ) {
            return true;
        } else {
            return bytes(acceptedMeasurements[measurementHash].tag).length > 0;
        }
    }

    /**
     * @dev Check if measurements are accepted
     * @param measurementHash Hash of the measurements to check
     */
    function isDeprecated(
        bytes32 measurementHash
    ) external view returns (bool) {
        return bytes(deprecatedMeasurements[measurementHash].tag).length > 0;
    }

    /**
     * @dev Get accepted measurement by tag
     */
    function getAcceptedMeasurement(
        bytes32 measurementHash
    ) external view returns (Measurements memory) {
        if (
            !initialIsDeprecated &&
            measurementHash == _getMeasurementHash(getInitialMeasurements())
        ) {
            Measurements memory initialMeasurements = getInitialMeasurements();

            if (_getMeasurementHash(initialMeasurements) == measurementHash) {
                return initialMeasurements;
            }
        }

        require(
            bytes(acceptedMeasurements[measurementHash].tag).length > 0,
            "Measurement not found"
        );
        return acceptedMeasurements[measurementHash];
    }

    /**
     * @dev Get count of accepted measurements
     */
    function getAcceptedCount() external view returns (uint256) {
        return acceptedTags.length;
    }

    function getMeasurementHash(
        Measurements calldata measurements
    ) external pure returns (bytes32) {
        return _getMeasurementHash(measurements);
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

    function _getMeasurementHash(
        Measurements memory m
    ) private pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    m.mrtd,
                    m.mrseam,
                    m.registrar_slots,
                    m.registrar_values
                )
            );
    }

    function getInitialMeasurements()
        public
        pure
        returns (Measurements memory)
    {
        Measurements memory m;

        m.tag = "Initial";

        m
            .mrtd = hex"f858414aef26d52a3b21614bab4bafab13b3ed62ebdd9d46a6be799228c2e27bc0d025cc6e4e90daff827cbe0316bbd9";

        m
            .mrseam = hex"49b66faa451d19ebbdbe89371b8daf2b65aa3984ec90110343e9e2eec116af08850fa20e3b1aa9a874d77a65380ee7e6";

        m.registrar_slots = new uint8[](4);
        m.registrar_slots[0] = 0;
        m.registrar_slots[1] = 1;
        m.registrar_slots[2] = 2;
        m.registrar_slots[3] = 3;

        m.registrar_values = new bytes[](4);
        m.registrar_values[0] = new bytes(48); // All zeros by default
        m.registrar_values[1] = new bytes(48);
        m.registrar_values[2] = new bytes(48);
        m.registrar_values[3] = new bytes(48);

        return m;
    }
}
