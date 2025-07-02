#!/bin/bash

# Build script for contracts
# This script builds the contracts using sforge

set -e

echo "Building contracts..."

# Build the contracts
# uses seismic sforge instead of forge
sforge build

echo "✅ Contracts built successfully!"
echo "JSON files are available in: out/" 