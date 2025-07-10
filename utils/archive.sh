#!/bin/bash

# Archive captured data for research

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="$(dirname "$SCRIPT_DIR")/data"
ARCHIVE_NAME="testbed_data_$(date +%Y%m%d_%H%M%S).tar.gz"

if [ ! -d "$DATA_DIR" ]; then
    echo "Error: Data directory not found: $DATA_DIR"
    exit 1
fi

echo "Creating archive: $ARCHIVE_NAME"

# Create archive excluding temporary files
tar -czf "$ARCHIVE_NAME" \
    --exclude="*.tmp" \
    --exclude="*.temp" \
    -C "$(dirname "$DATA_DIR")" \
    "$(basename "$DATA_DIR")"

echo "Archive created: $ARCHIVE_NAME"
echo "Size: $(du -h "$ARCHIVE_NAME" | cut -f1)"

# Show what's included
echo
echo "Archive contents:"
tar -tzf "$ARCHIVE_NAME" | head -20
if [ $(tar -tzf "$ARCHIVE_NAME" | wc -l) -gt 20 ]; then
    echo "... and $(($(tar -tzf "$ARCHIVE_NAME" | wc -l) - 20)) more files"
fi
