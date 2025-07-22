#!/bin/bash
set -e

log() { echo "[$(date +'%H:%M:%S')] POST-INIT: $1"; }

WP_PATH="/var/www/html/wordpress"

log "Starting WordPress post-initialization..."

# Ensure we're in the correct directory
cd $WP_PATH

# Wait for WordPress to be ready and database to be accessible
log "Waiting for WordPress and database to be ready..."
for i in {1..30}; do
    if [ -f "$WP_PATH/wp-config.php" ]; then
        # Test database connection
        if wp --allow-root db check 2>/dev/null; then
            log "Database connection successful"
            break
        else
            log "Database not ready yet, waiting... (attempt $i/30)"
        fi
    else
        log "wp-config.php not found yet, waiting... (attempt $i/30)"
    fi
    sleep 2
done

# Check if WordPress is already installed
if wp --allow-root core is-installed 2>/dev/null; then
    log "WordPress is already installed."
else
    if [ -f "$WP_PATH/wp-config.php" ]; then
        log "Running automated WordPress installation..."
        wp --allow-root core install \
          --url="${WP_URL:-http://localhost:8080/wordpress}" \
          --title="${WP_TITLE:-Security Testbed Victim}" \
          --admin_user="${WP_ADMIN_USER:-admin}" \
          --admin_password="${WP_ADMIN_PASSWORD:-admin}" \
          --admin_email="${WP_ADMIN_EMAIL:-admin@example.com}" \
          --skip-email || {
          log "WordPress installation failed"
          exit 1
        }
        log "WordPress installation completed successfully"
    else
        log "ERROR: wp-config.php not found!"
        exit 1
    fi
fi

# Set proper file permissions
chown -R www-data:www-data $WP_PATH
find $WP_PATH -type d -exec chmod 755 {} \;
find $WP_PATH -type f -exec chmod 644 {} \;

# Create a marker file to indicate successful setup
touch "$WP_PATH/.wp-configured"

log "WordPress post-initialization completed successfully"
