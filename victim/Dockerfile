FROM ubuntu:22.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
# Update and install essential tools (lightweight, no GUI)
RUN echo 'APT::Install-Recommends "0";' | tee -a /etc/apt/apt.conf.d/01norecommends && \
    echo 'APT::Install-Suggests "0";' | tee -a /etc/apt/apt.conf.d/01norecommends && \
    echo 'Acquire::ForceIPv4=true;' | tee -a /etc/apt/apt.conf.d/99force-ipv4 && \
    apt-get update && apt-get install -y \
    apache2 \
    mysql-server \
    php \
    php-mysql \
    libapache2-mod-php \
    php-curl \
    php-gd \
    php-mbstring \
    php-xml \
    php-zip \
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

# Create startup script
COPY start_services.sh /
RUN chmod +x /start_services.sh

# EXPOSE 80 22 3306 8081

CMD ["/start_services.sh"]