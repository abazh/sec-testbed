#!/bin/bash

# Start victim services
set -euo pipefail

log() { echo "[$(date +'%H:%M:%S')] $1" | tee -a /logs/startup.log; }

log "Starting victim services..."

# Start services
service mysql start && sleep 3
/setup_databases.sh
service ssh start
echo "Listen 8081" >> /etc/apache2/ports.conf
service apache2 start

# Create logs
mkdir -p /logs
{
    echo "WordPress: http://victim/wordpress"
    echo "OJS: http://victim:8081/ojs" 
    echo "Vulnerable Login: http://victim/vulnerable_login.php"
    echo "PHP Info: http://victim/info.php"
} | tee -a /logs/startup.log

log "All services started successfully"

# Keep container running
tail -f /var/log/apache2/access.log