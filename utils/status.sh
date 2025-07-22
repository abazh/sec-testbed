#!/bin/bash

# Enhanced Status Check Script
# Provides comprehensive status information for the security testbed

set -uo pipefail  # Removed -e to allow graceful handling of failed checks

# Color codes
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

# Configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
readonly PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Utility functions
status_icon() {
    case "$1" in
        "up"|"running"|"healthy") echo -e "${GREEN}✓${NC}" ;;
        "down"|"stopped"|"exited") echo -e "${RED}✗${NC}" ;;
        "starting"|"unhealthy") echo -e "${YELLOW}⚠${NC}" ;;
        *) echo -e "${BLUE}?${NC}" ;;
    esac
}

check_container_status() {
    local container_name="$1"
    local status=$(docker inspect --format='{{.State.Status}}' "$container_name" 2>/dev/null || echo "not_found")
    local health=$(docker inspect --format='{{.State.Health.Status}}' "$container_name" 2>/dev/null || echo "no_health_check")
    
    echo -n "$(status_icon "$status") $container_name: "
    
    if [ "$status" = "not_found" ]; then
        echo -e "${RED}Not found${NC}"
        return 1
    fi
    
    case "$status" in
        "running")
            if [ "$health" = "healthy" ]; then
                echo -e "${GREEN}Running (Healthy)${NC}"
            elif [ "$health" = "unhealthy" ]; then
                echo -e "${YELLOW}Running (Unhealthy)${NC}"
            elif [ "$health" = "starting" ]; then
                echo -e "${YELLOW}Running (Health Starting)${NC}"
            else
                echo -e "${GREEN}Running${NC}"
            fi
            ;;
        "exited")
            local exit_code=$(docker inspect --format='{{.State.ExitCode}}' "$container_name" 2>/dev/null || echo "unknown")
            echo -e "${RED}Exited (code: $exit_code)${NC}"
            ;;
        *)
            echo -e "${YELLOW}$status${NC}"
            ;;
    esac
}

check_service_accessibility() {
    local service_name="$1"
    local url="$2"
    local timeout="${3:-10}"
    
    echo -n "$(status_icon "") $service_name: "
    
    if curl -f --connect-timeout "$timeout" --max-time "$timeout" "$url" >/dev/null 2>&1; then
        echo -e "${GREEN}Accessible${NC}"
        return 0
    else
        echo -e "${RED}Not accessible${NC}"
        return 1
    fi
}

check_network_connectivity() {
    local from_container="$1"
    local to_ip="$2"
    local description="$3"
    
    echo -n "$(status_icon "") $description: "
    
    if docker exec "$from_container" ping -c 1 -W 5 "$to_ip" >/dev/null 2>&1; then
        echo -e "${GREEN}Connected${NC}"
        return 0
    else
        echo -e "${RED}No connectivity${NC}"
        return 1
    fi
}

show_resource_usage() {
    echo -e "\n${BLUE}=== Resource Usage ===${NC}"
    
    # Check if containers exist first
    local containers=("sec_switch" "sec_attacker" "sec_victim" "sec_monitor")
    local running_containers=()
    
    for container in "${containers[@]}"; do
        if docker ps --format "{{.Names}}" | grep -q "^${container}$"; then
            running_containers+=("$container")
        fi
    done
    
    if [ ${#running_containers[@]} -eq 0 ]; then
        echo "No containers running"
        return
    fi
    
    docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.BlockIO}}" "${running_containers[@]}" 2>/dev/null || echo "Unable to get stats"
}

show_network_info() {
    echo -e "\n${BLUE}=== Network Information ===${NC}"
    
    # Docker networks
    echo "Docker Networks:"
    docker network ls | grep -E "(NETWORK|sec-testbed)" || echo "No sec-testbed network found"
    
    # OVS Bridge info (if switch is running)
    if docker ps --format "{{.Names}}" | grep -q "^sec_switch$"; then
        echo -e "\nOVS Bridge Configuration:"
        docker exec sec_switch ovs-vsctl show 2>/dev/null | head -20 || echo "Unable to get OVS info"
        
        echo -e "\nOVS Bridge Ports:"
        docker exec sec_switch ovs-vsctl list-ports ovs-br0 2>/dev/null || echo "Unable to list OVS ports"
    fi
}

show_log_summary() {
    echo -e "\n${BLUE}=== Recent Log Summary ===${NC}"
    
    local data_dir="$PROJECT_DIR/data"
    
    if [ -d "$data_dir" ]; then
        echo "Data directories:"
        find "$data_dir" -type f -name "*.log" -o -name "*.json" -o -name "*.csv" -o -name "*.pcap" | head -10 | while read -r file; do
            local size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null || echo "unknown")
            local modified=$(stat -f%Sm -t"%Y-%m-%d %H:%M" "$file" 2>/dev/null || stat -c%y "$file" 2>/dev/null | cut -d' ' -f1-2 || echo "unknown")
            echo "  $(basename "$file") (${size} bytes, modified: ${modified})"
        done
    else
        echo "Data directory not found"
    fi
}

show_quick_commands() {
    echo -e "\n${BLUE}=== Quick Commands ===${NC}"
    echo "Container Access:"
    echo "  docker exec -it sec_attacker bash"
    echo "  docker exec -it sec_victim bash"
    echo "  docker exec -it sec_monitor bash"
    echo "  docker exec -it sec_switch bash"
    
    echo -e "\nAttack Commands:"
    echo "  docker exec -it sec_attacker /attack_scenarios/attack_tools.sh --automated"
    echo "  docker exec -it sec_attacker /attack_scenarios/attack_tools.sh --interactive"
    
    echo -e "\nMonitoring Commands:"
    echo "  docker exec -it sec_monitor python3 /scripts/dataset_generator.py"
    echo "  docker logs -f sec_monitor"
    
    echo -e "\nManagement Commands:"
    echo "  docker compose logs [service]"
    echo "  docker compose restart [service]"
    echo "  ./utils/cleanup.sh"
    echo "  ./utils/reset.sh"
}

main() {
    echo -e "${BLUE}=== Security Testbed Status v1.0 ===${NC}\n"
    
    # Change to project directory
    cd "$PROJECT_DIR"
    
    # Container Status
    echo -e "${BLUE}=== Container Status ===${NC}"
    local containers=("sec_switch" "sec_attacker" "sec_victim" "sec_monitor")
    local healthy_count=0
    
    for container in "${containers[@]}"; do
        if check_container_status "$container"; then
            ((healthy_count++))
        fi
    done
    
    echo -e "\nHealthy containers: $healthy_count/${#containers[@]}"
    
    # Service Accessibility (only if containers are running)
    if [ $healthy_count -gt 0 ]; then
        echo -e "\n${BLUE}=== Service Accessibility ===${NC}"
        check_service_accessibility "Victim Web" "http://localhost:8080/"
        check_service_accessibility "WordPress" "http://localhost:8080/wordpress/"
        check_service_accessibility "Vulnerable Login" "http://localhost:8080/vulnerable_login.php"
    fi
    
    # Network Connectivity (only if relevant containers are running)
    if docker ps --format "{{.Names}}" | grep -q "sec_attacker" && docker ps --format "{{.Names}}" | grep -q "sec_victim"; then
        echo -e "\n${BLUE}=== Network Connectivity ===${NC}"
        check_network_connectivity "sec_attacker" "100.64.0.20" "Attacker → Victim"
        if docker ps --format "{{.Names}}" | grep -q "sec_monitor"; then
            echo -e "$(status_icon "") Monitor → Victim: ${BLUE}Passive monitoring (no connectivity test needed)${NC}"
        fi
    fi
    
    # Resource usage
    show_resource_usage
    
    # Network information
    show_network_info
    
    # Log summary
    show_log_summary
    
    # Quick commands
    show_quick_commands
    
    # Overall status
    echo -e "\n${BLUE}=== Overall Status ===${NC}"
    if [ $healthy_count -eq ${#containers[@]} ]; then
        echo -e "$(status_icon "healthy") ${GREEN}All systems operational${NC}"
    elif [ $healthy_count -gt 0 ]; then
        echo -e "$(status_icon "unhealthy") ${YELLOW}Partial functionality ($healthy_count/${#containers[@]} containers healthy)${NC}"
    else
        echo -e "$(status_icon "down") ${RED}Testbed not running${NC}"
        echo "Run './start_testbed.sh' to start the testbed"
    fi
    
    echo ""
}

# Execute main function
main "$@"
