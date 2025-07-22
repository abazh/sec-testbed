#!/bin/bash

# Security Testbed Startup Script v2.0
# Enhanced with better error handling, logging, and health checks

set -euo pipefail

# Configuration
readonly SCRIPT_VERSION="2.0"
readonly LOG_FILE="/tmp/testbed_startup.log"
readonly MAX_WAIT_TIME=300  # 5 minutes
readonly HEALTH_CHECK_INTERVAL=10

# Color codes
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

# Logging functions
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date +'%Y-%m-%d %H:%M:%S')
    
    case "$level" in
        INFO)  echo -e "${BLUE}[INFO]${NC} $message" ;;
        WARN)  echo -e "${YELLOW}[WARN]${NC} $message" ;;
        ERROR) echo -e "${RED}[ERROR]${NC} $message" ;;
        SUCCESS) echo -e "${GREEN}[SUCCESS]${NC} $message" ;;
    esac
    
    echo "$timestamp [$level] $message" >> "$LOG_FILE"
}

log_info() { log INFO "$@"; }
log_warn() { log WARN "$@"; }
log_error() { log ERROR "$@"; }
log_success() { log SUCCESS "$@"; }

# Error handling
cleanup_on_error() {
    local exit_code=$?
    log_error "Script failed with exit code $exit_code"
    log_info "Cleaning up any partially started containers..."
    
    docker compose down --remove-orphans 2>/dev/null || true
    
    log_info "Startup log saved to: $LOG_FILE"
    exit $exit_code
}

trap cleanup_on_error ERR

# Utility functions
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    local missing_tools=()
    
    # Check Docker
    if ! command -v docker >/dev/null; then
        missing_tools+=("docker")
    elif ! docker info >/dev/null 2>&1; then
        log_error "Docker is installed but not running"
        return 1
    fi
    
    # Check Docker Compose
    if ! command -v docker >/dev/null || ! docker compose version >/dev/null 2>&1; then
        missing_tools+=("docker-compose")
    fi
    
    # Check required system capabilities
    if [ ! -e /dev/kvm ] && [ ! -e /proc/sys/net/bridge ]; then
        log_warn "Bridge networking capabilities may be limited"
    fi
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log_info "Please install the missing tools and try again"
        return 1
    fi
    
    log_success "All prerequisites satisfied"
    return 0
}

setup_environment() {
    log_info "Setting up environment..."
    
    # Create data directories
    local data_dirs=(
        "data/captures"
        "data/analysis" 
        "data/attacker_logs"
        "data/victim_logs"
        "data/switch_logs"
    )
    
    for dir in "${data_dirs[@]}"; do
        if mkdir -p "$dir"; then
            log_info "Created directory: $dir"
        else
            log_error "Failed to create directory: $dir"
            return 1
        fi
    done
    
    # Set appropriate permissions
    find data/ -type d -exec chmod 755 {} \; 2>/dev/null || true
    
    # Make attack scripts executable
    if [ -d "attacker/attack_scenarios" ]; then
        chmod +x attacker/attack_scenarios/*.sh 2>/dev/null || true
        log_info "Made attack scripts executable"
    fi
    
    # Copy environment file if it doesn't exist
    if [ ! -f ".env" ] && [ -f ".env.example" ]; then
        cp .env.example .env
        log_info "Created .env file from example"
    fi
    
    log_success "Environment setup completed"
    return 0
}

wait_for_container_health() {
    local container_name="$1"
    local max_wait="${2:-$MAX_WAIT_TIME}"
    local check_interval="${3:-$HEALTH_CHECK_INTERVAL}"
    
    log_info "Waiting for $container_name to become healthy..."
    
    local elapsed=0
    while [ $elapsed -lt $max_wait ]; do
        local health_status=$(docker inspect --format='{{.State.Health.Status}}' "$container_name" 2>/dev/null || echo "unknown")
        
        case "$health_status" in
            "healthy")
                log_success "$container_name is healthy"
                return 0
                ;;
            "unhealthy")
                log_error "$container_name health check failed"
                docker logs --tail 10 "$container_name" || true
                return 1
                ;;
            "starting"|"unknown")
                log_info "$container_name health status: $health_status (${elapsed}s elapsed)"
                ;;
        esac
        
        sleep $check_interval
        elapsed=$((elapsed + check_interval))
    done
    
    log_error "$container_name did not become healthy within ${max_wait}s"
    return 1
}

verify_network_connectivity() {
    log_info "Verifying network connectivity between containers..."
    
    # Wait a bit for networking to stabilize
    sleep 5
    
    # Test attacker -> victim connectivity
    if docker exec sec_attacker ping -c 1 -W 5 "${VICTIM_IP:-100.64.0.20}" >/dev/null 2>&1; then
        log_success "Attacker can reach victim"
    else
        log_error "Attacker cannot reach victim"
        return 1
    fi
    
    # Monitor container is passive and doesn't need connectivity testing
    # It captures traffic via OVS port mirroring, not active communication
    log_info "Skipping monitor connectivity test (passive monitoring node)"
    
    # Verify OVS bridge configuration
    # Load bridge name from .env if it exists
    local bridge_name="ovs-br0"  # default
    if [ -f .env ]; then
        bridge_name=$(grep "^OVS_BRIDGE_NAME=" .env | cut -d'=' -f2 | tr -d '"' | tr -d "'")
        [ -z "$bridge_name" ] && bridge_name="ovs-br0"
    fi
    
    if docker exec sec_switch ovs-vsctl show | grep -q "Bridge $bridge_name"; then
        log_success "OVS bridge is properly configured"
    else
        log_error "OVS bridge configuration issue"
        return 1
    fi
    
    log_success "Network connectivity verified"
    return 0
}

start_containers() {
    log_info "Starting security testbed containers..."
    
    # Clean up any existing containers
    docker compose down --remove-orphans 2>/dev/null || true
    
    # Build and start containers
    if docker compose up -d --build --remove-orphans; then
        log_success "Containers started successfully"
    else
        log_error "Failed to start containers"
        return 1
    fi
    
    # Wait for containers to be running
    log_info "Waiting for containers to start..."
    sleep 10
    
    # Check container status
    local containers=("sec_switch" "sec_attacker" "sec_victim" "sec_monitor")
    for container in "${containers[@]}"; do
        if docker ps --format "table {{.Names}}" | grep -q "^${container}$"; then
            log_info "$container is running"
        else
            log_error "$container failed to start"
            docker logs "$container" 2>/dev/null || true
            return 1
        fi
    done
    
    return 0
}

verify_services() {
    log_info "Verifying services are accessible..."
    
    # Wait for services to initialize
    sleep 15
    
    # Check victim web services
    local victim_url="http://localhost:8080"
    if curl -f --connect-timeout 10 --max-time 30 "$victim_url" >/dev/null 2>&1; then
        log_success "Victim web service is accessible"
    else
        log_warn "Victim web service not yet accessible (may still be initializing)"
    fi
    
    # Check WordPress
    local wp_url="http://localhost:8080/wordpress"
    if curl -f --connect-timeout 10 --max-time 30 "$wp_url" >/dev/null 2>&1; then
        log_success "WordPress is accessible"
    else
        log_warn "WordPress not yet accessible (may still be initializing)"
    fi
    
    return 0
}

show_status() {
    log_info "Final status check..."
    
    echo ""
    echo "=== Container Status ==="
    docker compose ps
    
    echo ""
    echo "=== Network Information ==="
    docker network ls | grep sec-testbed || true
    
    echo ""
    echo "=== OVS Configuration ==="
    docker exec sec_switch ovs-vsctl show 2>/dev/null || echo "OVS not accessible"
    
    echo ""
    echo "=== Service URLs ==="
    echo "  Victim Web:    http://localhost:8080/"
    echo "  WordPress:     http://localhost:8080/wordpress/"
    echo "  Vulnerable:    http://localhost:8080/vulnerable_login.php"
    
    echo ""
    echo "=== Container Access ==="
    echo "  Attacker:  docker exec -it sec_attacker bash"
    echo "  Victim:    docker exec -it sec_victim bash"
    echo "  Monitor:   docker exec -it sec_monitor bash"
    echo "  Switch:    docker exec -it sec_switch bash"
    
    echo ""
    echo "=== Quick Commands ==="
    echo "  Status:        ./utils/status.sh"
    echo "  Cleanup:       ./utils/cleanup.sh"
    echo "  Reset:         ./utils/reset.sh"
    echo "  Archive:       ./utils/archive.sh"
}

main() {
    echo "=== Security Testbed Startup v$SCRIPT_VERSION ==="
    echo ""
    
    # Initialize log file
    echo "$(date +'%Y-%m-%d %H:%M:%S') [INFO] Security Testbed startup initiated" > "$LOG_FILE"
    
    # Execute startup sequence
    check_prerequisites
    setup_environment
    start_containers
    
    # Wait for critical containers to be healthy
    wait_for_container_health "sec_switch" 120
    wait_for_container_health "sec_victim" 180
    
    # Verify connectivity and services
    verify_network_connectivity
    verify_services
    
    show_status
    
    echo ""
    echo "=== 🚀 Testbed Ready ==="
    echo ""
    
    log_success "Security testbed startup completed successfully"
    log_info "Startup log saved to: $LOG_FILE"
}

# Execute main function
main "$@"
echo ""
echo "Services:"
echo "  WordPress: http://victim/wordpress"
echo "  OJS:       http://victim:8081"
echo "  Vuln Page: http://victim/vulnerable_login.php"
echo ""
echo "Quick Start:"
echo "  Run attacks: docker exec -it sec_attacker ./attack_scenarios/attack_tools.sh"
echo "  View logs:   ls -la data/"