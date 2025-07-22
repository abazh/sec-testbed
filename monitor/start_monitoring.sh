#!/bin/bash

# Streamlined Network Monitoring for Dataset Generation
set -euo pipefail

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
INTERFACE="eth0"

log() { echo "[$(date +'%H:%M:%S')] [MONITOR] $1" | tee -a /logs/monitor.log; }

log "Starting Security Testbed Network Monitor"

# Setup directories
mkdir -p /captures /logs /analysis
# Fix permissions for monitoring processes
chmod 777 /captures /logs /analysis

# Wait for network interface
log "Waiting for network interface..."
while ! ip link show $INTERFACE >/dev/null 2>&1; do
    sleep 2
done
log "Interface $INTERFACE ready"

# Start unified packet capture (full capture only)
start_capture() {
    log "Starting full packet capture..."
    tcpdump -i $INTERFACE -w "/captures/full_capture_$TIMESTAMP.pcap" -C 100 -z gzip &
    TCPDUMP_PID=$!
    log "Full packet capture started (PID: $TCPDUMP_PID)"
}

# Start flow monitoring with all important features
start_argus() {
    log "Starting Argus flow monitoring..."
    argus -i $INTERFACE -w /captures/flows_$TIMESTAMP.arg &
    ARGUS_PID=$!
    log "Argus flow monitoring started (PID: $ARGUS_PID)"
}

# Attack correlation processor
process_attack_markers() {
    log "Starting attack marker processor..."
    while inotifywait -e create /captures/; do
        # Process new attack markers for dataset labeling
        python3 /scripts/dataset_generator.py --correlate-attacks &
    done &
    INOTIFY_PID=$!
}

# Cleanup function
cleanup() {
    log "Shutting down monitoring..."
    for pid in $TCPDUMP_PID $ARGUS_PID $INOTIFY_PID; do
        [ -n "$pid" ] && kill $pid 2>/dev/null || true
    done
}
trap cleanup EXIT TERM INT

# Start all monitoring services
log "=== Starting monitoring services ==="
start_capture
start_argus
# process_attack_markers

# Log startup
{
    echo "$(date): Network monitoring started on $INTERFACE"
    echo "Full capture: /captures/full_capture_$TIMESTAMP.pcap"
    echo "Flow data: /captures/flows_$TIMESTAMP.arg"
} | tee -a /logs/monitor_startup.log

log "=== Monitoring Active ==="
log "✓ Full packet capture (tcpdump)"
log "✓ Flow monitoring (argus)"
# log "✓ Attack correlation processor"

# Keep the container running and monitor processes
while true; do
    # Check if critical processes are still running
    if ! kill -0 $TCPDUMP_PID 2>/dev/null; then
        log "ERROR: tcpdump process died, restarting..."
        start_capture
    fi
    
    if ! kill -0 $ARGUS_PID 2>/dev/null; then
        log "ERROR: argus process died, restarting..."
        start_argus
    fi
    
    # Wait 30 seconds before next check
    sleep 30
done