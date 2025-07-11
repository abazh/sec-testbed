#!/bin/bash

# Health check script for monitor container

# Check if tcpdump is running
if ! pgrep tcpdump > /dev/null; then
    echo "FAIL: tcpdump not running"
    exit 1
fi

# Check if argus is running
if ! pgrep argus > /dev/null; then
    echo "FAIL: argus not running"
    exit 1
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

echo "OK: All monitoring services healthy"
exit 0
