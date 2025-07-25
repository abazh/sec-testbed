#!/bin/bash

# OpenVSwitch Configuration for Security Testbed
# Streamlined version with reduced boilerplate

set -euo pipefail

# Configuration - Use same environment variables as Docker Compose
readonly OVS_BRIDGE="${OVS_BRIDGE_NAME:-ovs-br0}"
readonly DOCKER_NETWORK="sec-testbed"  # Fixed network name from docker-compose
readonly NETWORK_SUBNET="${TESTBED_SUBNET:-100.64.0.0/24}"
readonly BRIDGE_IP="${TESTBED_GATEWAY:-100.64.0.1}/24"
readonly ATTACKER_IP="${ATTACKER_IP:-100.64.0.10}"
readonly VICTIM_IP="${VICTIM_IP:-100.64.0.20}"
readonly MONITOR_IP="${MONITOR_IP:-100.64.0.30}"

# Container names - Use same as Docker Compose
readonly ATTACKER_CONTAINER="sec_attacker"
readonly VICTIM_CONTAINER="sec_victim"  
readonly MONITOR_CONTAINER="sec_monitor"

# Runtime configuration
readonly CONTAINER_WAIT_TIMEOUT="${TESTBED_CONTAINER_TIMEOUT:-60}"
readonly CONNECTIVITY_TIMEOUT="${TESTBED_CONNECTIVITY_TIMEOUT:-2}"
readonly HEALTH_CHECK_INTERVAL="${TESTBED_HEALTH_INTERVAL:-60}"

# Logging
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" >&2
}

die() {
    log "ERROR: $1"
    exit 1
}

# Configuration validation and logging
validate_config() {
    log "=== Configuration Validation ==="
    log "OVS Bridge: $OVS_BRIDGE"
    log "Docker Network: $DOCKER_NETWORK"
    log "Network Subnet: $NETWORK_SUBNET"
    log "Bridge IP: $BRIDGE_IP"
    log "Container IPs: Attacker=$ATTACKER_IP, Victim=$VICTIM_IP, Monitor=$MONITOR_IP"
    log "Container Names: $ATTACKER_CONTAINER, $VICTIM_CONTAINER, $MONITOR_CONTAINER"
    log "Timeouts: Container=${CONTAINER_WAIT_TIMEOUT}s, Connectivity=${CONNECTIVITY_TIMEOUT}s, Health=${HEALTH_CHECK_INTERVAL}s"
    
    # Validate network configuration
    if ! [[ "$NETWORK_SUBNET" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
        die "Invalid network subnet format: $NETWORK_SUBNET"
    fi
    
    if ! [[ "$BRIDGE_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
        die "Invalid bridge IP format: $BRIDGE_IP"
    fi
    
    # Validate IP addresses
    for ip_var in "ATTACKER_IP:$ATTACKER_IP" "VICTIM_IP:$VICTIM_IP" "MONITOR_IP:$MONITOR_IP"; do
        local name="${ip_var%:*}"
        local ip="${ip_var#*:}"
        if ! [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            die "Invalid IP address for $name: $ip"
        fi
    done
    
    log "✓ Configuration validation passed"
}

# Cleanup handler
cleanup() {
    log "Received termination signal, running cleanup..."
    
    # Kill background health monitoring process
    jobs -p | xargs -r kill 2>/dev/null || true
    
    # Run the dedicated cleanup script
    if [ -f "/cleanup_pre_stop.sh" ]; then
        log "Running dedicated pre-stop cleanup script..."
        bash /cleanup_pre_stop.sh
    else
        # Fallback cleanup if script not found
        log "Pre-stop script not found, running fallback cleanup..."
        
        # Remove mirrors first
        ovs-vsctl --if-exists destroy Mirror mymirror 2>/dev/null || true
        ovs-vsctl --if-exists clear Bridge "$OVS_BRIDGE" mirrors 2>/dev/null || true
        
        # Remove the OVS bridge completely
        if ovs-vsctl br-exists "$OVS_BRIDGE" 2>/dev/null; then
            log "Removing OVS bridge '$OVS_BRIDGE'"
            ovs-vsctl del-br "$OVS_BRIDGE" 2>/dev/null || true
            log "Removed OVS bridge '$OVS_BRIDGE'"
        fi
    fi
    
    # Optional: Restore original veth names if needed
    # This helps with Docker cleanup but is not strictly necessary
    for veth_name in veth-attacker veth-victim veth-monitor; do
        if ip link show "$veth_name" >/dev/null 2>&1; then
            # Find an available vethXXX name
            for i in $(seq 1 999); do
                new_name=$(printf "veth%07x" $i)
                if ! ip link show "$new_name" >/dev/null 2>&1; then
                    ip link set "$veth_name" name "$new_name" 2>/dev/null || true
                    break
                fi
            done
        fi
    done
    
    log "Cleanup completed"
    exit 0
}
trap cleanup TERM INT

# Verify prerequisites
ovs-vsctl show >/dev/null 2>&1 || die "OpenVSwitch not running"

# Get container veth interface and rename it for easy identification
get_veth_for_container() {
    local container_name=$1
    local container_id peer_ifindex veth new_veth_name old_veth
    
    container_id=$(docker ps -q --filter "name=$container_name" 2>/dev/null) || return 1
    [ -n "$container_id" ] || return 1
    
    # Create meaningful name based on container
    case "$container_name" in
        "$ATTACKER_CONTAINER") new_veth_name="veth-attacker" ;;
        "$VICTIM_CONTAINER") new_veth_name="veth-victim" ;;
        "$MONITOR_CONTAINER") new_veth_name="veth-monitor" ;;
        *) new_veth_name="veth-${container_name#sec_}" ;;
    esac
    
    # Check if already renamed
    if ip link show "$new_veth_name" >/dev/null 2>&1; then
        echo "$new_veth_name"
        return 0
    fi
    
    # Retry with exponential backoff to find original veth
    for i in {1..5}; do
        peer_ifindex=$(docker exec "$container_name" cat /sys/class/net/eth0/iflink 2>/dev/null | tr -d '\r\n')
        if [ -n "$peer_ifindex" ]; then
            veth=$(ip link show | awk -v idx="$peer_ifindex" -F': ' '$1 == idx {print $2}' | awk -F'@' '{print $1}')
            if [ -n "$veth" ] && [ "$veth" != "$new_veth_name" ]; then
                old_veth="$veth"
                # Remove old veth from OVS bridge if it exists there
                if ovs-vsctl list-ports "$OVS_BRIDGE" 2>/dev/null | grep -q "^$old_veth$"; then
                    log "Removing old veth $old_veth from OVS bridge before rename"
                    ovs-vsctl del-port "$OVS_BRIDGE" "$old_veth" 2>/dev/null || true
                fi
                
                # Rename the veth interface
                log "Renaming $veth to $new_veth_name"
                ip link set "$veth" name "$new_veth_name" || {
                    log "Failed to rename $veth, using original name"
                    echo "$veth"
                    return 0
                }
                echo "$new_veth_name"
                return 0
            elif [ -n "$veth" ]; then
                echo "$veth"
                return 0
            fi
        fi
        sleep $((i * 2))
    done
    return 1
}

# Wait for containers to be ready
wait_for_containers() {
    log "Waiting for containers..."
    local count=0
    local max_wait=$((CONTAINER_WAIT_TIMEOUT / 2))  # Check every 2 seconds
    
    while [ $count -lt $max_wait ]; do
        if docker network ls | grep -q "$DOCKER_NETWORK" && \
           docker ps | grep -q "$ATTACKER_CONTAINER" && \
           docker ps | grep -q "$VICTIM_CONTAINER" && \
           docker ps | grep -q "$MONITOR_CONTAINER"; then
            return 0
        fi
        sleep 2
        count=$((count + 1))
    done
    die "Containers not ready after ${CONTAINER_WAIT_TIMEOUT}s"
}

# Remove Linux bridge completely
remove_linux_bridge() {
    local bridge_name=$1
    [ -d "/sys/class/net/$bridge_name" ] || return 0
    
    log "Removing Linux bridge: $bridge_name"
    
    # Remove all interfaces
    if [ -d "/sys/class/net/$bridge_name/brif" ]; then
        for iface in $(ls "/sys/class/net/$bridge_name/brif/" 2>/dev/null || echo ""); do
            [ -d "/sys/class/net/$iface" ] || continue
            ip link set "$iface" nomaster 2>/dev/null || true
        done
    fi
    
    # Remove bridge
    ip link set "$bridge_name" down 2>/dev/null || true
    brctl delbr "$bridge_name" 2>/dev/null || true
    
    # Verify removal
    [ ! -d "/sys/class/net/$bridge_name" ] || die "Failed to remove bridge $bridge_name"
}

# Add port to OVS bridge
add_port_to_ovs() {
    local bridge=$1 interface=$2
    
    # Check if already added
    ovs-vsctl list-ports "$bridge" | grep -q "^$interface$" && return 0
    
    # Free from any existing bridge
    ip link set "$interface" nomaster 2>/dev/null || true
    ip link set "$interface" up
    
    # Add to OVS
    ovs-vsctl add-port "$bridge" "$interface" || die "Failed to add port $interface"
    log "Added port $interface to OVS bridge"
}

# Configure OVS bridge and mirroring
configure_ovs() {
    log "Configuring OVS bridge and mirroring..."
    
    wait_for_containers
    
    # Clean up any orphaned veth interfaces from previous runs
    cleanup_orphaned_veths() {
        log "Cleaning up orphaned veth interfaces..."
        if ovs-vsctl br-exists "$OVS_BRIDGE" 2>/dev/null; then
            # Get all ports currently in the bridge
            local bridge_ports=$(ovs-vsctl list-ports "$OVS_BRIDGE" 2>/dev/null || echo "")
            for port in $bridge_ports; do
                # Check if the interface actually exists
                if ! ip link show "$port" >/dev/null 2>&1; then
                    log "Removing orphaned port $port from OVS bridge"
                    ovs-vsctl del-port "$OVS_BRIDGE" "$port" 2>/dev/null || true
                fi
            done
        fi
    }
    
    cleanup_orphaned_veths
    
    # Handle existing Docker bridge
    if [ -d "/sys/class/net/$OVS_BRIDGE/bridge" ]; then
        log "Converting Docker bridge to OVS bridge..."
        local existing_interfaces=$(ls /sys/class/net/$OVS_BRIDGE/brif/ 2>/dev/null || echo "")
        
        remove_linux_bridge "$OVS_BRIDGE"
        ovs-vsctl add-br "$OVS_BRIDGE"
        
        # Re-add interfaces that were on Docker bridge
        for iface in $existing_interfaces; do
            [ -d "/sys/class/net/$iface" ] && add_port_to_ovs "$OVS_BRIDGE" "$iface"
        done
        
        ip addr add "$BRIDGE_IP" dev "$OVS_BRIDGE" 2>/dev/null || true
    else
        ovs-vsctl br-exists "$OVS_BRIDGE" || ovs-vsctl add-br "$OVS_BRIDGE"
        ip addr add "$BRIDGE_IP" dev "$OVS_BRIDGE" 2>/dev/null || true
    fi
    
    ip link set "$OVS_BRIDGE" up
    ovs-vsctl set bridge "$OVS_BRIDGE" fail_mode=standalone
    
    # Get container interfaces
    log "Finding container interfaces..."
    local attacker_if victim_if monitor_if
    
    attacker_if=$(get_veth_for_container "$ATTACKER_CONTAINER") || die "Cannot find attacker interface"
    victim_if=$(get_veth_for_container "$VICTIM_CONTAINER") || die "Cannot find victim interface"
    monitor_if=$(get_veth_for_container "$MONITOR_CONTAINER") || die "Cannot find monitor interface"
    
    log "Interfaces: Attacker=$attacker_if, Victim=$victim_if, Monitor=$monitor_if"
    
    # Verify interface naming
    log "Interface mapping:"
    log "  - Container $ATTACKER_CONTAINER → $attacker_if"
    log "  - Container $VICTIM_CONTAINER → $victim_if" 
    log "  - Container $MONITOR_CONTAINER → $monitor_if"
    
    # Add interfaces to OVS
    add_port_to_ovs "$OVS_BRIDGE" "$attacker_if"
    add_port_to_ovs "$OVS_BRIDGE" "$victim_if"
    add_port_to_ovs "$OVS_BRIDGE" "$monitor_if"
    
    # Configure port mirroring
    log "Configuring port mirroring..."
    ovs-vsctl -- --if-exists destroy Mirror mymirror 2>/dev/null || true
    ovs-vsctl -- --if-exists clear Bridge "$OVS_BRIDGE" mirrors 2>/dev/null || true

    # Get the port UUID for the monitor interface
    monitor_port_uuid=$(ovs-vsctl get Port "$monitor_if" _uuid) || die "Failed to get monitor port UUID"
    
    ovs-vsctl -- --id=@m create Mirror name=mymirror select_all=true output_port="$monitor_port_uuid" \
              -- set bridge "$OVS_BRIDGE" mirrors=@m || die "Failed to create mirror"
    
    log "Port mirroring configured successfully"
}

# Main execution
main() {
    log "=== Security Testbed OVS Configuration ===="
    
    # Validate configuration first
    validate_config
    
    configure_ovs
    
    # Verify configuration
    ovs-vsctl list Mirror mymirror >/dev/null 2>&1 || die "Mirror verification failed"
    
    # Test connectivity
    log "Testing connectivity..."
    for ip in $ATTACKER_IP $VICTIM_IP $MONITOR_IP; do
        if ping -c 1 -W "$CONNECTIVITY_TIMEOUT" "$ip" >/dev/null 2>&1; then
            log "✓ $ip reachable"
        else
            log "✗ $ip not reachable"
        fi
    done
    
    # Log final configuration
    mkdir -p /logs
    {
        echo "$(date): OVS Security Testbed Configuration"
        echo "Bridge: $OVS_BRIDGE"
        echo "Network: $NETWORK_SUBNET"
        ovs-vsctl show
        echo ""
        ovs-vsctl list Mirror
    } > /logs/ovs_config.log
    
    log "=== OVS Configuration Complete ===="
    log "✓ Bridge configured with port mirroring"
    log "✓ Monitor receives all traffic passively"
    
    # Health monitoring loop
    while true; do
        sleep "$HEALTH_CHECK_INTERVAL"
        if ! ovs-vsctl show >/dev/null 2>&1; then
            log "OVS connection lost, restarting..."
            service openvswitch-switch restart
            sleep 10
            configure_ovs
        fi
    done &
    
    # Wait for background health monitoring
    wait
}

main "$@"