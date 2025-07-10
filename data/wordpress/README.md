# WordPress Application Directory

This directory contains WordPress files mounted into the victim container.

## Purpose

- Provides persistent storage for WordPress installation
- Allows customization of WordPress content and plugins
- Enables file-based attacks (e.g., file upload vulnerabilities)

## Structure

```
wordpress/
├── wp-admin/           # WordPress admin interface
├── wp-content/         # Themes, plugins, uploads
├── wp-includes/        # WordPress core files
├── wp-config.php       # WordPress configuration
└── index.php           # Main entry point
```

## Usage

The victim container mounts this directory at `/var/www/html/wordpress`. WordPress is accessible at:
- Internal: `http://100.64.0.20/wordpress`
- External: `http://localhost:8080/wordpress`

## Development

- Add vulnerable plugins here for testing
- Customize themes for attack scenarios
- Upload files for file inclusion attacks

## Database

WordPress uses the `wordpress` database created by `victim/setup_databases.sh` with credentials:
- User: `wpuser`
- Password: `wppass`
