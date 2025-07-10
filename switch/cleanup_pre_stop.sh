#!/bin/bash

# OVS Cleanup Script for Pre-Stop Hook
# This script runs when the container receives a TERM signal

set -e

# Configuration
OVS_BRIDGE="ovs-br0"
MIRROR_NAME="mymirror"

# Function for logging
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] PRE-STOP: $1"
}

log_info() {
    log "INFO: $1"
}

log_success() {
    log "SUCCESS: ✓ $1"
}

# Clean up OVS configuration before container stops
cleanup_ovs_on_stop() {
    log_info "Running pre-stop OVS cleanup..."
    
    # Remove mirrors first
    ovs-vsctl --if-exists destroy Mirror "$MIRROR_NAME" 2>/dev/null || true
    ovs-vsctl --if-exists clear Bridge "$OVS_BRIDGE" mirrors 2>/dev/null || true
    
    # Remove the OVS bridge completely
    if ovs-vsctl br-exists "$OVS_BRIDGE" 2>/dev/null; then
        log_info "Removing OVS bridge '$OVS_BRIDGE'"
        ovs-vsctl del-br "$OVS_BRIDGE" 2>/dev/null || true
        log_success "Removed OVS bridge '$OVS_BRIDGE'"
    fi
    
    log_success "Pre-stop OVS cleanup completed"
}

# Run cleanup
cleanup_ovs_on_stop
