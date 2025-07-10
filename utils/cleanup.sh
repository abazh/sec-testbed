#!/bin/bash

# Security Testbed Cleanup Script
# Simple cleanup for logs and packet captures

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="$(dirname "$SCRIPT_DIR")/data"
DAYS=${1:-7}  # Default: keep files from last 7 days

show_help() {
    echo "Usage: $0 [days]"
    echo "  days: Keep files newer than N days (default: 7)"
    echo ""
    echo "Examples:"
    echo "  $0        # Clean files older than 7 days"
    echo "  $0 3      # Clean files older than 3 days"
    echo "  $0 0      # Clean all files"
}

# Check arguments
if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    show_help
    exit 0
fi

if ! [[ "$DAYS" =~ ^[0-9]+$ ]]; then
    echo "Error: Days must be a number"
    show_help
    exit 1
fi

if [ ! -d "$DATA_DIR" ]; then
    echo "Error: Data directory not found: $DATA_DIR"
    exit 1
fi

echo "Cleaning files older than $DAYS days from $DATA_DIR"
echo

# Clean logs
echo "Cleaning logs..."
find "$DATA_DIR" -name "*.log" -type f -mtime +$DAYS -delete 2>/dev/null || true

# Clean packet captures  
echo "Cleaning packet captures..."
find "$DATA_DIR" -name "*.pcap" -type f -mtime +$DAYS -delete 2>/dev/null || true
find "$DATA_DIR" -name "*.pcapng" -type f -mtime +$DAYS -delete 2>/dev/null || true
find "$DATA_DIR" -name "*.arg" -type f -mtime +$DAYS -delete 2>/dev/null || true

# Clean analysis files
echo "Cleaning analysis files..."
find "$DATA_DIR" -name "*.json" -type f -mtime +$DAYS -delete 2>/dev/null || true
find "$DATA_DIR" -name "*.csv" -type f -mtime +$DAYS -delete 2>/dev/null || true
find "$DATA_DIR" -name "*.tmp" -type f -mtime +$DAYS -delete 2>/dev/null || true

# Remove empty directories
find "$DATA_DIR" -type d -empty -delete 2>/dev/null || true

echo "Cleanup completed!"
echo "Current data directory size:"
du -sh "$DATA_DIR" 2>/dev/null || echo "Unable to calculate size"
