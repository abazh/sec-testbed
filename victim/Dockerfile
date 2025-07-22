# Multi-stage build for security testbed victim container
FROM ubuntu:24.04 AS base

# Build arguments
ARG DEBIAN_FRONTEND=noninteractive
ARG BUILD_DATE
ARG VERSION=1.0

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive \
    TZ=UTC \
    PYTHONUNBUFFERED=1 \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Install security and performance optimizations
RUN echo 'APT::Install-Recommends "0";' > /etc/apt/apt.conf.d/01norecommends && \
    echo 'APT::Install-Suggests "0";' > /etc/apt/apt.conf.d/01norecommends && \
    echo 'Acquire::ForceIPv4=true;' > /etc/apt/apt.conf.d/99force-ipv4 && \
    apt-get update && apt-get install -y --no-install-recommends \
    # Web server and PHP
    apache2 \
    ca-certificates \
    mysql-server \
    php8.3 \
    php8.3-mysql \
    libapache2-mod-php8.3 \
    php8.3-curl \
    php8.3-gd \
    php8.3-mbstring \
    php8.3-xml \
    php8.3-zip \
    # System utilities
    wget \
    curl \
    unzip \
    openssh-server \
    vim \
    nano \
    net-tools \
    iputils-ping \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /var/cache/apt/archives/*

# Configure Apache
RUN a2enmod rewrite
RUN echo "ServerName localhost" >> /etc/apache2/apache2.conf

# Create vulnerable SSH configuration
RUN mkdir /var/run/sshd
RUN echo 'root:vulnerable' | chpasswd
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Download and setup WordPress (commonly used version for security testing)
WORKDIR /var/www/html
RUN wget --no-check-certificate https://wordpress.org/wordpress-5.8.tar.gz \
    && tar -xzf wordpress-5.8.tar.gz \
    && rm wordpress-5.8.tar.gz \
    && chown -R www-data:www-data wordpress

# Copy WordPress configuration
COPY wordpress/wp-config.php /var/www/html/wordpress/wp-config.php
RUN chown www-data:www-data /var/www/html/wordpress/wp-config.php

RUN curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar && \
    chmod +x wp-cli.phar && \
    mv wp-cli.phar /usr/local/bin/wp && \
    wp --info

# Download and setup OJS (commonly used version)  
RUN wget --no-check-certificate https://pkp.sfu.ca/ojs/download/ojs-3.3.0-4.tar.gz \
    && tar -xzf ojs-3.3.0-4.tar.gz \
    && mv ojs-3.3.0-4 ojs \
    && rm ojs-3.3.0-4.tar.gz \
    && chown -R www-data:www-data ojs

# Create vulnerable PHP info page
RUN echo "<?php phpinfo(); ?>" > /var/www/html/info.php

# Create a simple vulnerable login page
COPY vulnerable_login.php /var/www/html/
COPY setup_databases.sh /
RUN chmod +x /setup_databases.sh

# Configure Apache virtual hosts
COPY apache_config.conf /etc/apache2/sites-available/testbed.conf
RUN a2ensite testbed.conf
RUN a2dissite 000-default.conf

# Create startup script and set permissions  
COPY start_services.sh /
COPY scripts/ /scripts/
RUN chmod +x /start_services.sh /scripts/*.sh 2>/dev/null || true

# Production stage
FROM base AS production

# Copy all configured files from base stage
COPY --from=base / /

# EXPOSE 80 22 3306 8081

CMD ["/start_services.sh"]