#!/bin/bash
# Database connection test script

echo "=== MySQL Connection Test ==="

# Test 1: Check if MySQL is running
echo "1. Checking MySQL service status..."
if service mysql status; then
    echo "✓ MySQL service is running"
else
    echo "✗ MySQL service is not running"
    exit 1
fi

# Test 2: Test root connection
echo ""
echo "2. Testing MySQL root connection..."
if mysql -u root -p"${MYSQL_ROOT_PASSWORD:-vulnerable123}" -e "SHOW DATABASES;" 2>/dev/null; then
    echo "✓ MySQL root connection successful"
else
    echo "✗ MySQL root connection failed"
    echo "Attempting without password..."
    if mysql -u root -e "SHOW DATABASES;" 2>/dev/null; then
        echo "✓ MySQL root connection successful (no password)"
    else
        echo "✗ MySQL root connection failed completely"
    fi
fi

# Test 3: Test WordPress user connection
echo ""
echo "3. Testing WordPress user connection..."
WP_USER="${WP_USER:-wpuser}"
WP_PASSWORD="${WP_PASSWORD:-wppass}"
WP_DATABASE="${WP_DATABASE:-wordpress}"

if mysql -u "$WP_USER" -p"$WP_PASSWORD" -e "USE $WP_DATABASE; SHOW TABLES;" 2>/dev/null; then
    echo "✓ WordPress user connection successful"
    echo "Database: $WP_DATABASE"
    echo "User: $WP_USER"
else
    echo "✗ WordPress user connection failed"
    echo "Attempted database: $WP_DATABASE"
    echo "Attempted user: $WP_USER"
fi

# Test 4: Check WordPress configuration
echo ""
echo "4. Checking WordPress configuration..."
WP_PATH="/var/www/html/wordpress"
if [ -f "$WP_PATH/wp-config.php" ]; then
    echo "✓ wp-config.php exists"
    if cd "$WP_PATH" && wp --allow-root db check 2>/dev/null; then
        echo "✓ WordPress database connection via WP-CLI successful"
    else
        echo "✗ WordPress database connection via WP-CLI failed"
    fi
else
    echo "✗ wp-config.php not found"
fi

echo ""
echo "=== Test completed ==="
