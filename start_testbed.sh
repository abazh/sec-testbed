#!/bin/bash

# Security Testbed Startup Script
set -euo pipefail

log() { echo "[$(date +'%H:%M:%S')] $1"; }

echo "=== Security Testbed Startup ===="

# Prerequisites check
command -v docker >/dev/null || { echo "Error: Docker not found"; exit 1; }
command -v docker compose >/dev/null || { echo "Error: docker compose not found"; exit 1; }
docker info >/dev/null 2>&1 || { echo "Error: Docker not running"; exit 1; }

log "Creating data directories..."
mkdir -p data/{captures,analysis,attacker_logs,victim_logs,switch_logs}
# Only change permissions for directories and files we own
find data/ -user $(whoami) -exec chmod 755 {} \; 2>/dev/null || true
chmod +x attacker/attack_scenarios/*.sh 2>/dev/null || true

# Build and start
log "Starting security testbed..."
docker compose up -d --build --remove-orphans

log "Waiting for containers to start..."
sleep 10

# Wait for switch to be fully healthy
log "Waiting for switch to be fully ready..."
while ! docker exec sec_switch ovs-vsctl show >/dev/null 2>&1; do
    log "Switch still initializing..."
    sleep 5
done
log "Switch is ready"

# Wait a bit more for monitor to initialize
log "Waiting for monitor to initialize..."
sleep 5

# Status check
log "Container status:"
docker compose ps

echo ""
echo "=== Testbed Ready ===="
echo ""
echo "Container Access:"
echo "  Attacker:  docker exec -it sec_attacker bash"
echo "  Victim:    docker exec -it sec_victim bash" 
echo "  Monitor:   docker exec -it sec_monitor bash"
echo ""
echo "Services:"
echo "  Juice Shop: http://victim:3000"
echo ""
echo "Quick Start:"
echo "  Run attacks: docker exec -it sec_attacker ./attack_scenarios/attack_tools.sh"
echo "  View logs:   ls -la data/"