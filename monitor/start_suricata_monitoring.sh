#!/bin/bash

# Suricata Network Monitoring for ML Dataset Generation
set -euo pipefail

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
INTERFACE="eth0"

log() { echo "[$(date +'%H:%M:%S')] [SURICATA] $1" | tee -a /logs/monitor.log; }

log "Starting Security Testbed Suricata Monitor"

# Setup directories with proper permissions
mkdir -p /captures /logs /analysis /var/log/suricata /var/run/suricata
chmod 755 /captures /logs /analysis /var/log/suricata /var/run/suricata

# Wait for network interface
log "Waiting for network interface $INTERFACE..."
while ! ip link show $INTERFACE >/dev/null 2>&1; do
    sleep 2
done
log "Interface $INTERFACE ready"

# Update Suricata rules
log "Updating Suricata rules..."
suricata-update --no-test --quiet || {
    log "Warning: Could not update rules, using default rules"
    # Create minimal rule set for basic detection
    cat > /var/lib/suricata/rules/suricata.rules << 'EOF'
# Basic attack detection rules for testbed
alert http any any -> any any (msg:"HTTP GET Request"; flow:established,to_server; http.method; content:"GET"; classtype:protocol-command-decode; sid:1000001; rev:1;)
alert http any any -> any any (msg:"HTTP POST Request"; flow:established,to_server; http.method; content:"POST"; classtype:protocol-command-decode; sid:1000002; rev:1;)
alert tcp any any -> any any (msg:"TCP SYN Packet"; flags:S; classtype:protocol-command-decode; sid:1000003; rev:1;)
alert icmp any any -> any any (msg:"ICMP Packet"; classtype:icmp-event; sid:1000004; rev:1;)
alert tcp any any -> any 22 (msg:"SSH Connection"; flow:to_server,established; classtype:protocol-command-decode; sid:1000005; rev:1;)
alert tcp any any -> any 3000 (msg:"Connection to Juice Shop"; flow:to_server; classtype:web-application-attack; sid:1000006; rev:1;)
alert http any any -> any any (msg:"Potential SQL Injection"; flow:established,to_server; content:"union"; nocase; http_uri; classtype:web-application-attack; sid:1000007; rev:1;)
alert http any any -> any any (msg:"Potential XSS Attack"; flow:established,to_server; content:"script"; nocase; http_uri; classtype:web-application-attack; sid:1000008; rev:1;)
EOF
}

# Test Suricata configuration
log "Testing Suricata configuration..."
if ! suricata -T -c /etc/suricata/suricata.yaml; then
    log "ERROR: Suricata configuration test failed"
    exit 1
fi
log "Suricata configuration test passed"

# Start Suricata in IDS mode
start_suricata() {
    log "Starting Suricata IDS on interface $INTERFACE..."
    suricata -c /etc/suricata/suricata.yaml -i $INTERFACE --pidfile /var/run/suricata/suricata.pid -D
    
    # Wait for Suricata to start
    sleep 5
    
    if [ -f /var/run/suricata/suricata.pid ]; then
        SURICATA_PID=$(cat /var/run/suricata/suricata.pid)
        log "Suricata started successfully (PID: $SURICATA_PID)"
    else
        log "ERROR: Failed to start Suricata"
        exit 1
    fi
}

# Process eve.json for ML features
start_eve_processor() {
    log "Starting eve.json processor for ML dataset generation..."
    python3 /scripts/eve_processor.py --input /var/log/suricata/eve.json --output /analysis/ &
    EVE_PROCESSOR_PID=$!
    log "Eve.json processor started (PID: $EVE_PROCESSOR_PID)"
}

# Attack correlation processor
process_attack_markers() {
    log "Starting attack marker correlation..."
    while inotifywait -e create /captures/ 2>/dev/null; do
        # Process new attack markers for dataset labeling
        python3 /scripts/ml_dataset_generator.py --correlate-attacks --eve-log /var/log/suricata/eve.json &
    done &
    INOTIFY_PID=$!
}

# Cleanup function
cleanup() {
    log "Shutting down monitoring..."
    
    # Stop attack correlation
    [ -n "${INOTIFY_PID:-}" ] && kill $INOTIFY_PID 2>/dev/null || true
    
    # Stop eve processor
    [ -n "${EVE_PROCESSOR_PID:-}" ] && kill $EVE_PROCESSOR_PID 2>/dev/null || true
    
    # Stop Suricata
    if [ -f /var/run/suricata/suricata.pid ]; then
        SURICATA_PID=$(cat /var/run/suricata/suricata.pid)
        log "Stopping Suricata (PID: $SURICATA_PID)..."
        kill $SURICATA_PID 2>/dev/null || true
        sleep 3
        # Force kill if still running
        kill -9 $SURICATA_PID 2>/dev/null || true
        rm -f /var/run/suricata/suricata.pid
    fi
    
    log "Monitoring shutdown complete"
}
trap cleanup EXIT TERM INT

# Start all monitoring services
log "=== Starting Suricata monitoring services ==="
start_suricata
start_eve_processor
process_attack_markers

# Log startup information
{
    echo "$(date): Suricata monitoring started on $INTERFACE"
    echo "Eve.json log: /var/log/suricata/eve.json"
    echo "Fast log: /var/log/suricata/fast.log"
    echo "Stats log: /var/log/suricata/stats.log"
    echo "ML analysis output: /analysis/"
} | tee -a /logs/monitor_startup.log

log "=== Suricata Monitoring Active ==="
log "✓ Suricata IDS/IPS engine"
log "✓ Eve.json generation for ML"
log "✓ Attack correlation processor"
log "✓ ML dataset generation"

# Monitor eve.json file size and rotation
monitor_eve_json() {
    while true; do
        if [ -f /var/log/suricata/eve.json ]; then
            # Rotate eve.json if it gets too large (>100MB)
            size=$(stat -f%z /var/log/suricata/eve.json 2>/dev/null || stat -c%s /var/log/suricata/eve.json 2>/dev/null || echo 0)
            if [ $size -gt 104857600 ]; then
                log "Rotating large eve.json file (${size} bytes)"
                mv /var/log/suricata/eve.json "/var/log/suricata/eve.json.$(date +%Y%m%d_%H%M%S)"
                # Signal Suricata to reopen log files
                if [ -f /var/run/suricata/suricata.pid ]; then
                    kill -USR2 $(cat /var/run/suricata/suricata.pid) 2>/dev/null || true
                fi
            fi
        fi
        sleep 300  # Check every 5 minutes
    done &
}

monitor_eve_json

# Keep the container running and monitor processes
while true; do
    # Check if Suricata is still running
    if [ -f /var/run/suricata/suricata.pid ]; then
        SURICATA_PID=$(cat /var/run/suricata/suricata.pid)
        if ! kill -0 $SURICATA_PID 2>/dev/null; then
            log "ERROR: Suricata process died, restarting..."
            start_suricata
        fi
    else
        log "ERROR: Suricata PID file missing, restarting..."
        start_suricata
    fi
    
    # Check eve processor
    if ! kill -0 ${EVE_PROCESSOR_PID:-0} 2>/dev/null; then
        log "WARNING: Eve processor died, restarting..."
        start_eve_processor
    fi
    
    # Wait 30 seconds before next check
    sleep 30
done
