#!/bin/bash
set -e  # Exit on error

# Define paths
DB_DIR="$HOME/.local/share/reth/5124/db"
BACKUP_FILE="$DB_DIR/seismic_reth_backup.tar.lz4"
MDBX_FILE="$DB_DIR/mdbx.dat"

echo "Creating backup..."
sudo tar --use-compress-program=lz4 -cvPf "$BACKUP_FILE" "$MDBX_FILE"
echo "Backup saved to: $BACKUP_FILE"
