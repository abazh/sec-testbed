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
    netcat-openbsd \
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

# Install Node.js and npm for Juice Shop - update certificates first
RUN apt-get update && apt-get install -y ca-certificates curl gnupg \
    && curl -fsSL https://deb.nodesource.com/setup_18.x | bash - \
    && apt-get install -y nodejs

# Download and setup OWASP Juice Shop
WORKDIR /opt
RUN wget --no-check-certificate https://github.com/juice-shop/juice-shop/releases/download/v15.3.0/juice-shop-15.3.0_node18_linux_x64.tgz \
    && tar -xzf juice-shop-15.3.0_node18_linux_x64.tgz \
    && rm juice-shop-15.3.0_node18_linux_x64.tgz \
    && chown -R www-data:www-data juice-shop_15.3.0

# Create a simple info page for the testbed
RUN echo "<h1>Security Testbed - Victim Container</h1><p>OWASP Juice Shop running on port 3000</p>" > /var/www/html/index.html

# Configure Apache for basic info page
RUN echo "ServerName localhost" >> /etc/apache2/apache2.conf

# Create startup script for Juice Shop
COPY start_juiceshop.sh /
RUN chmod +x /start_juiceshop.sh

# EXPOSE 3000 22 80

CMD ["/start_juiceshop.sh"]