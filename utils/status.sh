#!/bin/bash

# Show status of the security testbed

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DATA_DIR="$PROJECT_ROOT/data"

echo "Security Testbed Status"
echo "======================"
echo

# Container status
echo "Container Status:"
cd "$PROJECT_ROOT"
docker-compose ps 2>/dev/null || echo "No containers running"
echo

# Data directory size
if [ -d "$DATA_DIR" ]; then
    echo "Data Directory Usage:"
    du -sh "$DATA_DIR"/* 2>/dev/null | sort -hr || echo "No data files found"
    echo
    echo "Total: $(du -sh "$DATA_DIR" 2>/dev/null | cut -f1)"
else
    echo "Data directory not found"
fi
echo

# Recent files
echo "Recent Files (last 24 hours):"
if [ -d "$DATA_DIR" ]; then
    find "$DATA_DIR" -type f -mtime -1 -exec ls -lh {} \; 2>/dev/null | head -10
    echo
fi

# Network info
echo "Docker Networks:"
docker network ls --filter name=sec-testbed 2>/dev/null || echo "No testbed networks found"
