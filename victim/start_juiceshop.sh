#!/bin/bash

# Start victim services with Juice Shop
set -euo pipefail

log() { echo "[$(date +'%H:%M:%S')] $1" | tee -a /logs/startup.log; }

log "Starting victim services with OWASP Juice Shop..."

# Start basic services
service ssh start
service apache2 start

# Create logs directory
mkdir -p /logs

# Start Juice Shop
log "Starting OWASP Juice Shop on port 3000..."
cd /opt/juice-shop_15.3.0
export NODE_ENV=production
export PORT=3000

# Start Juice Shop in background and capture PID
nohup npm start > /logs/juiceshop.log 2>&1 &
JUICESHOP_PID=$!

log "Juice Shop started with PID: $JUICESHOP_PID"

{
    echo "OWASP Juice Shop: http://victim:3000"
    echo "Apache Info Page: http://victim/"
    echo "SSH Access: ssh root@victim (password: vulnerable)"
} | tee -a /logs/startup.log

log "All services started successfully"

# Wait for Juice Shop to be ready
while ! nc -z localhost 3000; do
    log "Waiting for Juice Shop to start..."
    sleep 2
done

log "Juice Shop is ready and listening on port 3000"

# Keep container running by monitoring Juice Shop process
while kill -0 $JUICESHOP_PID 2>/dev/null; do
    sleep 30
done

log "Juice Shop process stopped, exiting..."
exit 1
