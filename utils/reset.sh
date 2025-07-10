#!/bin/bash

# Reset the security testbed environment

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "Resetting Security Testbed..."

# Stop all containers
echo "Stopping containers..."
cd "$PROJECT_ROOT"
docker-compose down -v --remove-orphans 2>/dev/null || true

# Clean all data
echo "Cleaning all data..."
"$SCRIPT_DIR/cleanup.sh" 0

# Remove Docker volumes
echo "Removing Docker volumes..."
docker volume prune -f 2>/dev/null || true

# Remove unused networks
echo "Cleaning Docker networks..."
docker network prune -f 2>/dev/null || true

echo "Reset completed!"
echo
echo "To start fresh, run: ./start_testbed.sh"
