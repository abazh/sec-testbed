#!/bin/bash

# Health check for Suricata monitoring container

# Check if Suricata is running
if [ -f /var/run/suricata/suricata.pid ]; then
    SURICATA_PID=$(cat /var/run/suricata/suricata.pid)
    if ! kill -0 $SURICATA_PID 2>/dev/null; then
        echo "FAIL: Suricata process not running"
        exit 1
    fi
else
    echo "FAIL: Suricata PID file not found"
    exit 1
fi

# Check if eve.json is being written to
if [ -f /var/log/suricata/eve.json ]; then
    # Check if file was modified in the last 5 minutes
    if [ $(find /var/log/suricata/eve.json -mmin -5 | wc -l) -eq 0 ]; then
        echo "WARNING: eve.json not updated recently"
        # Don't fail health check, just warn
    fi
else
    echo "WARNING: eve.json not found"
fi

# Check if network interface is available
if ! ip link show eth0 > /dev/null 2>&1; then
    echo "FAIL: eth0 interface not available"
    exit 1
fi

# Check if capture directory is accessible
if [ ! -d "/captures" ] || [ ! -w "/captures" ]; then
    echo "FAIL: /captures directory not accessible"
    exit 1
fi

# Check if analysis directory exists and is writable
if [ ! -d /analysis ] || [ ! -w /analysis ]; then
    echo "FAIL: Analysis directory not accessible"
    exit 1
fi

echo "OK: Suricata monitoring healthy"
exit 0
