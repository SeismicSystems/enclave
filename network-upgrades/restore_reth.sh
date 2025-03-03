#!/bin/bash

set -e  # Exit on error

# Define paths
DB_DIR="$HOME/.local/share/reth/5124/db"
BACKUP_FILE="$DB_DIR/seismic_reth_backup.tar.lz4"
MDBX_FILE="$DB_DIR/mdbx.dat"

echo "Restoring database from backup..."
if [[ -f "$BACKUP_FILE" ]]; then
    cd "$DB_DIR"
    sudo tar --use-compress-program=lz4 -xvf "$BACKUP_FILE"
else
    echo "Backup file not found: $BACKUP_FILE"
    exit 1
fi

echo "Verifying restoration..."
if [[ -f "$MDBX_FILE" ]]; then
    echo "Database restored successfully."
else
    echo "Error: mdbx.dat not found after extraction!"
    exit 1
fi
