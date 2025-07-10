# Multi-stage build for security testbed attacker container
FROM ubuntu:22.04 AS base

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Update and install essential tools (lightweight, no GUI)
RUN echo 'APT::Install-Recommends "0";' | tee -a /etc/apt/apt.conf.d/01norecommends && \
    echo 'APT::Install-Suggests "0";' | tee -a /etc/apt/apt.conf.d/01norecommends && \
    echo 'Acquire::ForceIPv4=true;' | tee -a /etc/apt/apt.conf.d/99force-ipv4 && \
    apt-get update && apt-get install -y --no-install-recommends \
    # Network scanning and enumeration
    nmap \
    # DDoS tools
    hping3 \
    # SQL injection tools
    sqlmap \
    # Brute force tools
    hydra \
    # Web application testing
    nikto \
    dirb \
    # Network tools
    netcat-openbsd \
    socat \
    tcpdump \
    # System tools
    net-tools \
    iputils-ping \
    iproute2 \
    curl \
    wget \
    vim \
    nano \
    git \
    python3 \
    python3-pip \
    python3-dev \
    build-essential \
    # Additional lightweight tools
    dnsutils \
    whois \
    openssl \
    openssh-client \
    telnet \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /var/cache/apt/archives/* \
    && rm -rf /tmp/*

# Create non-root user for better security
RUN groupadd -r attacker && useradd -r -g attacker -d /home/attacker -s /bin/bash attacker \
    && mkdir -p /home/attacker \
    && chown -R attacker:attacker /home/attacker

# Install Python packages for additional attack capabilities
RUN pip3 install --no-cache-dir --upgrade pip \
    && pip3 install --no-cache-dir \
    requests \
    beautifulsoup4 \
    paramiko \
    scapy \
    impacket

# Create directories for logs and scripts
RUN mkdir -p /logs /attack_scenarios 

# Create a simple wordlist for testing
RUN mkdir -p /usr/share/wordlists && \
    echo -e "admin\npassword\n123456\npassword123\nadmin123\nroot\ntest\nguest\nuser\nwordpress\nletmein\nwelcome\nqwerty" > /usr/share/wordlists/rockyou.txt

# Add health check script
RUN echo '#!/bin/bash\nping -c 1 100.64.0.20 >/dev/null 2>&1' > /usr/local/bin/healthcheck.sh \
    && chmod +x /usr/local/bin/healthcheck.sh

# Working directory
WORKDIR /attack_scenarios

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD /usr/local/bin/healthcheck.sh

# Security labels
LABEL maintainer="Security Testbed Team" \
      version="1.0" \
      description="Educational security testing container - Attacker simulation" \
      security.level="educational" \
      usage="isolated-environment-only"

CMD ["/bin/bash"]