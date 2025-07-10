#!/bin/bash

# Setup databases for WordPress and OJS
set -euo pipefail

service mysql start && sleep 3

# Create databases and users
mysql << 'EOF'
CREATE DATABASE IF NOT EXISTS wordpress;
CREATE USER IF NOT EXISTS 'wpuser'@'%' IDENTIFIED BY 'wppass';
GRANT ALL PRIVILEGES ON wordpress.* TO 'wpuser'@'%';

CREATE DATABASE IF NOT EXISTS ojs;
CREATE USER IF NOT EXISTS 'ojsuser'@'%' IDENTIFIED BY 'ojspass';
GRANT ALL PRIVILEGES ON ojs.* TO 'ojsuser'@'%';

CREATE DATABASE IF NOT EXISTS testbed;
USE testbed;
CREATE TABLE IF NOT EXISTS users (id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(50), password VARCHAR(50));
INSERT INTO users (username, password) VALUES ('admin', 'admin'), ('user', 'password123');

FLUSH PRIVILEGES;
EOF

echo "Databases setup completed."