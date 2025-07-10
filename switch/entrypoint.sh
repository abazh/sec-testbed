#!/bin/bash
set -e

# Function for logging
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

# Handle termination signals
trap 'log "Received SIGTERM or SIGINT, shutting down..."; service openvswitch-switch stop; exit 0' TERM INT

# Startup message
log "Starting Mininet Docker container..."

# Start Open vSwitch service
log "Starting Open vSwitch service..."
service openvswitch-switch start || {
    log "ERROR: Failed to start Open vSwitch service"
    exit 1
}

# Print OVS status
log "Open vSwitch is running with the following configuration:"
ovs-vsctl show

# Execute the command passed to docker
log "Initialization complete"
exec "$@"