# WordPress Setup Troubleshooting Guide

## Overview
This guide helps troubleshoot WordPress database connection issues in the security testbed victim container.

## Common Issues and Solutions

### 1. Database Connection Errors
**Symptoms:**
- "Permission denied" in PHP error logs
- WordPress setup page fails to connect to database
- "Unknown column 'wp_' in 'field list'" errors

**Solutions:**
1. Check if MySQL is running: `service mysql status`
2. Test database connection: `/scripts/test-db.sh`
3. Verify database credentials in environment variables
4. Check wp-config.php has correct database settings

### 2. Empty wp-config.php
**Symptoms:**
- WordPress redirects to setup page every time
- Database connection fails

**Solution:**
- The wp-config.php should be automatically created during build
- If missing, it will be recreated from the Docker build

### 3. WordPress Installation Loop
**Symptoms:**
- WordPress keeps asking for installation
- Admin page shows "not installed"

**Solutions:**
1. Check if `.wp-configured` marker file exists in `/var/www/html/wordpress/`
2. Manually run WordPress installation:
   ```bash
   cd /var/www/html/wordpress
   wp --allow-root core install \
     --url="http://localhost:8080/wordpress" \
     --title="Security Testbed" \
     --admin_user="admin" \
     --admin_password="adminpass" \
     --admin_email="admin@example.com" \
     --skip-email
   ```

### 4. Permission Issues
**Symptoms:**
- File write errors
- Plugin/theme installation fails

**Solutions:**
1. Fix ownership: `chown -R www-data:www-data /var/www/html/wordpress`
2. Fix permissions: `chmod -R 755 /var/www/html/wordpress`

## Manual Setup Steps

If automatic setup fails, run these commands in the victim container:

1. **Start services:**
   ```bash
   service mysql start
   service apache2 start
   ```

2. **Setup database:**
   ```bash
   /setup_databases.sh
   ```

3. **Test database connection:**
   ```bash
   /scripts/test-db.sh
   ```

4. **Install WordPress:**
   ```bash
   cd /var/www/html/wordpress
   wp --allow-root core install \
     --url="http://localhost:8080/wordpress" \
     --title="Security Testbed Victim" \
     --admin_user="admin" \
     --admin_password="adminpass" \
     --admin_email="admin@example.com" \
     --skip-email
   ```

## Environment Variables

The following environment variables control WordPress setup:

- `WP_DATABASE`: WordPress database name (default: wordpress)
- `WP_USER`: WordPress database user (default: wpuser)
- `WP_PASSWORD`: WordPress database password (default: wppass)
- `WP_URL`: WordPress site URL (default: http://localhost:8080/wordpress)
- `WP_ADMIN_USER`: WordPress admin username (default: admin)
- `WP_ADMIN_PASSWORD`: WordPress admin password (default: adminpass)
- `WP_ADMIN_EMAIL`: WordPress admin email (default: admin@example.com)
- `MYSQL_ROOT_PASSWORD`: MySQL root password (default: vulnerable123)

## Default Credentials

- **WordPress Admin:** admin / adminpass
- **MySQL Root:** root / vulnerable123  
- **MySQL WordPress User:** wpuser / wppass
- **SSH Root:** root / vulnerable

## Log Files

Check these log files for debugging:

- Apache error log: `/var/log/apache2/error.log`
- Apache access log: `/var/log/apache2/access.log`
- Startup log: `/logs/startup.log`
- WordPress debug log: `/var/www/html/wordpress/wp-content/debug.log`

## Testing

After setup, test these URLs:

- WordPress site: http://localhost:8080/wordpress
- WordPress admin: http://localhost:8080/wordpress/wp-admin
- PHP info: http://localhost:8080/info.php
- Vulnerable login: http://localhost:8080/vulnerable_login.php
