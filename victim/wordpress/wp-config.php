<?php
/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the installation.
 * You don't have to use the web site, you can copy this file to "wp-config.php"
 * and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * Database settings
 * * Secret keys
 * * Database table prefix
 * * ABSPATH
 *
 * @link https://wordpress.org/support/article/editing-wp-config-php/
 *
 * @package WordPress
 */

// ** Database settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );

/** Database username */
define( 'DB_USER', 'wpuser' );

/** Database password */
define( 'DB_PASSWORD', 'wppass' );

/** Database hostname - using 127.0.0.1 instead of localhost to force TCP connection */
define( 'DB_HOST', '127.0.0.1' );

/** Database charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8' );

/** The database collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

/**#@+
 * Authentication unique keys and salts.
 * Intentionally weak for security testing - DO NOT USE IN PRODUCTION
 *
 * @since 2.6.0
 */
define( 'AUTH_KEY',         'testbed-auth-key' );
define( 'SECURE_AUTH_KEY',  'testbed-secure-auth-key' );
define( 'LOGGED_IN_KEY',    'testbed-logged-in-key' );
define( 'NONCE_KEY',        'testbed-nonce-key' );
define( 'AUTH_SALT',        'testbed-auth-salt' );
define( 'SECURE_AUTH_SALT', 'testbed-secure-auth-salt' );
define( 'LOGGED_IN_SALT',   'testbed-logged-in-salt' );
define( 'NONCE_SALT',       'testbed-nonce-salt' );

/**#@-*/

/**
 * WordPress database table prefix.
 *
 * You can have multiple installations in one database if you give each
 * a unique prefix. Only numbers, letters, and underscores please!
 */
$table_prefix = 'wp_';

/**
 * For developers: WordPress debugging mode.
 *
 * Change this to true to enable the display of notices during development.
 * It is strongly recommended that plugin and theme developers use WP_DEBUG
 * in their development environments.
 *
 * For information on other constants that can be used for debugging,
 * visit the documentation.
 *
 * @link https://wordpress.org/support/article/debugging-in-wordpress/
 */
define( 'WP_DEBUG', true );
define( 'WP_DEBUG_LOG', true );
define( 'WP_DEBUG_DISPLAY', false );


/* Disable all WordPress automatic updates */
define('WP_AUTO_UPDATE_CORE', false);
define('AUTOMATIC_UPDATER_DISABLED', true);

/* Add any custom values between this line and the "stop editing" comment. */

/* WordPress URLs for security testbed - Dynamic configuration */
if (!empty($_ENV['WP_URL'])) {
    // Use environment variable if set
    define( 'WP_HOME', $_ENV['WP_URL'] );
    define( 'WP_SITEURL', $_ENV['WP_URL'] );
} elseif (isset($_SERVER['HTTP_HOST'])) {
    // Dynamic URL based on request host
    $protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'];
    $wp_url = $protocol . '://' . $host . '/wordpress';
    define( 'WP_HOME', $wp_url );
    define( 'WP_SITEURL', $wp_url );
} else {
    // Fallback to localhost
    define( 'WP_HOME', 'http://localhost:8080/wordpress' );
    define( 'WP_SITEURL', 'http://localhost:8080/wordpress' );
}

/* Disable file editing for security (but easily bypassable for testing) */
define( 'DISALLOW_FILE_EDIT', false );

/* That's all, stop editing! Happy publishing. */

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';
