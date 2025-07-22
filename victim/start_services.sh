#!/bin/bash

# Start victim services
set -euo pipefail

log() { echo "[$(date +'%H:%M:%S')] $1" | tee -a /logs/startup.log; }

log "Starting victim services..."

# Create logs directory
mkdir -p /logs

# Start MySQL and setup databases
log "Starting MySQL and setting up databases..."
service mysql start && sleep 5
/setup_databases.sh

# Setup WordPress if not already configured
WP_PATH="/var/www/html/wordpress"
if [ -f "$WP_PATH/wp-config.php" ] && [ ! -f "$WP_PATH/.wp-configured" ]; then
    log "Running WordPress post-initialization..."
    if [ -f "/scripts/post-init.sh" ]; then
        # Try to make executable, but don't fail if it doesn't work
        chmod +x /scripts/post-init.sh 2>/dev/null || true
        /scripts/post-init.sh || log "WordPress post-init failed, but continuing..."
    else
        log "Post-init script not found, running basic setup..."
        cd $WP_PATH
        
        # Wait for database to be ready
        sleep 3
        
        # Check if WordPress is already installed
        if ! wp --allow-root core is-installed 2>/dev/null; then
            log "Installing WordPress core..."
            wp --allow-root core install \
                --url="${WP_URL:-http://localhost:8080/wordpress}" \
                --title="${WP_TITLE:-Security Testbed Victim}" \
                --admin_user="${WP_ADMIN_USER:-admin}" \
                --admin_password="${WP_ADMIN_PASSWORD:-adminpass}" \
                --admin_email="${WP_ADMIN_EMAIL:-admin@example.com}" \
                --skip-email || {
                log "WordPress installation failed, but continuing..."
            }
            log "WordPress installation completed"
        else
            log "WordPress is already installed"
        fi
        
        # Set proper permissions
        chown -R www-data:www-data $WP_PATH
        chmod -R 755 $WP_PATH
        
        # Create configuration marker
        touch "$WP_PATH/.wp-configured"
    fi
fi

# Start other services
log "Starting SSH and Apache services..."
service ssh start
service apache2 start

# Create service information
{
    echo "=== Security Testbed Victim Services ==="
    echo "WordPress: http://victim/wordpress (or http://localhost:8080/wordpress)"
    echo "WordPress Admin: http://victim/wordpress/wp-admin"
    echo "OJS: http://victim/ojs (or http://localhost:8080/ojs)" 
    echo "Vulnerable Login: http://victim/vulnerable_login.php"
    echo "PHP Info: http://victim/info.php"
    echo "=== Default Credentials ==="
    echo "WordPress Admin: ${WP_ADMIN_USER:-admin} / ${WP_ADMIN_PASSWORD:-adminpass}"
    echo "MySQL Root: root / ${MYSQL_ROOT_PASSWORD:-vulnerable123}"
    echo "MySQL WordPress: ${WP_USER:-wpuser} / ${WP_PASSWORD:-wppass}"
    echo "SSH Root: root / vulnerable"
} | tee -a /logs/startup.log

log "All services started successfully"

# Keep container running and show Apache logs
tail -f /var/log/apache2/access.log /var/log/apache2/error.log