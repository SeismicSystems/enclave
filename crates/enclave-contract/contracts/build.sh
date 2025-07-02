#!/bin/bash

# Build script for contracts
# This script builds the contracts using sforge

set -e

echo "Building contracts..."

# Build the contracts
# uses seismic sforge instead of forge
if sforge build | grep -q "Nothing to compile"; then
    echo "Nothing to compile. Something probably went wrong."
else
    echo "✅ Contracts built successfully!"
    echo "JSON files are available in: out/"
fi 