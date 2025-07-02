#!/bin/bash

# Build script for contracts
# This script builds the contracts and copies the JSON files to the test directory

set -e

echo "Building contracts..."

# Build the contracts
# uses seismic sforge instead of forge
sforge build

echo "Copying JSON files to test directory..."

# Create test directory if it doesn't exist
mkdir -p ../../../tests/integration/snapshot/

# Copy the JSON files
cp out/UpgradeOperator.sol/UpgradeOperator.json ../../../tests/integration/snapshot/
cp out/UpgradeOperatorFactory.sol/UpgradeOperatorFactory.json ../../../tests/integration/snapshot/

echo "✅ Contracts built and JSON files copied successfully!"
echo "Files copied to: ../../../tests/integration/snapshot/" 