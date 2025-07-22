#!/bin/bash

# Setup databases for WordPress and OJS
set -euo pipefail

log() { echo "[$(date +'%H:%M:%S')] DB SETUP: $1"; }

log "Starting MySQL service..."
service mysql start && sleep 5

# Set MySQL root password if provided
if [ -n "${MYSQL_ROOT_PASSWORD:-}" ]; then
    log "Setting MySQL root password..."
    mysqladmin -u root password "${MYSQL_ROOT_PASSWORD}"
fi

log "Creating databases and users..."

# Create databases and users with proper error handling
mysql -u root ${MYSQL_ROOT_PASSWORD:+-p${MYSQL_ROOT_PASSWORD}} << EOF
-- Drop existing users if they exist to avoid conflicts
DROP USER IF EXISTS '${WP_USER:-wpuser}'@'localhost';
DROP USER IF EXISTS '${WP_USER:-wpuser}'@'%';
DROP USER IF EXISTS 'ojsuser'@'localhost';
DROP USER IF EXISTS 'ojsuser'@'%';

-- Create WordPress database and user
CREATE DATABASE IF NOT EXISTS \`${WP_DATABASE:-wordpress}\` CHARACTER SET utf8 COLLATE utf8_general_ci;
CREATE USER '${WP_USER:-wpuser}'@'localhost' IDENTIFIED WITH mysql_native_password BY '${WP_PASSWORD:-wppass}';
CREATE USER '${WP_USER:-wpuser}'@'%' IDENTIFIED WITH mysql_native_password BY '${WP_PASSWORD:-wppass}';
GRANT ALL PRIVILEGES ON \`${WP_DATABASE:-wordpress}\`.* TO '${WP_USER:-wpuser}'@'localhost';
GRANT ALL PRIVILEGES ON \`${WP_DATABASE:-wordpress}\`.* TO '${WP_USER:-wpuser}'@'%';

-- Create OJS database and user
CREATE DATABASE IF NOT EXISTS ojs CHARACTER SET utf8 COLLATE utf8_general_ci;
CREATE USER 'ojsuser'@'localhost' IDENTIFIED WITH mysql_native_password BY 'ojspass';
CREATE USER 'ojsuser'@'%' IDENTIFIED WITH mysql_native_password BY 'ojspass';
GRANT ALL PRIVILEGES ON ojs.* TO 'ojsuser'@'localhost';
GRANT ALL PRIVILEGES ON ojs.* TO 'ojsuser'@'%';

-- Create testbed database for vulnerable applications
CREATE DATABASE IF NOT EXISTS testbed CHARACTER SET utf8 COLLATE utf8_general_ci;
USE testbed;
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY, 
    username VARCHAR(50), 
    password VARCHAR(50)
);
INSERT IGNORE INTO users (username, password) VALUES 
    ('admin', 'admin'), 
    ('user', 'password123'),
    ('test', 'test'),
    ('guest', 'guest123');

-- Grant access to testbed database for WordPress user (for vulnerable scenarios)
GRANT ALL PRIVILEGES ON testbed.* TO '${WP_USER:-wpuser}'@'localhost';
GRANT ALL PRIVILEGES ON testbed.* TO '${WP_USER:-wpuser}'@'%';

-- Create dedicated user for vulnerable login page
CREATE USER IF NOT EXISTS 'testuser'@'localhost' IDENTIFIED WITH mysql_native_password BY 'testpass';
CREATE USER IF NOT EXISTS 'testuser'@'%' IDENTIFIED WITH mysql_native_password BY 'testpass';
GRANT ALL PRIVILEGES ON testbed.* TO 'testuser'@'localhost';
GRANT ALL PRIVILEGES ON testbed.* TO 'testuser'@'%';

FLUSH PRIVILEGES;
EOF

if [ $? -eq 0 ]; then
    log "Databases setup completed successfully."
else
    log "ERROR: Database setup failed!"
    exit 1
fi

# Test database connections
log "Testing database connections..."
mysql -u "${WP_USER:-wpuser}" -p"${WP_PASSWORD:-wppass}" -e "SHOW DATABASES;" || {
    log "ERROR: WordPress user cannot connect to database!"
    exit 1
}

log "Database setup and testing completed successfully."