# Multi-stage build for security testbed monitor container with Suricata
FROM ubuntu:24.04 AS base

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Install dependencies and add Suricata 8 repository
RUN echo 'APT::Install-Recommends "0";' | tee -a /etc/apt/apt.conf.d/01norecommends && \
    echo 'APT::Install-Suggests "0";' | tee -a /etc/apt/apt.conf.d/01norecommends && \
    echo 'Acquire::ForceIPv4=true;' | tee -a /etc/apt/apt.conf.d/99force-ipv4 && \
    apt-get update && apt-get -y install autoconf automake build-essential cargo \
    cbindgen libjansson-dev libpcap-dev libpcre2-dev libtool \
    libyaml-dev make pkg-config rustc zlib1g-dev \
    gnupg \
    lsb-release \
    ca-certificates \
    # Supporting tools
    tcpdump \
    tshark \
    # Network analysis tools
    ngrep \
    # System tools
    net-tools \
    iputils-ping \
    iproute2 \
    curl \
    wget \
    vim \
    nano \
    cron \
    jq \
    # Python and analysis libraries
    python3 \
    python3-pip \
    python3-dev \
    build-essential \
    # Additional monitoring tools
    iftop \
    nethogs \
    procps \
    inotify-tools \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Add OISF repository for Suricata 8.x and install
RUN apt-get update && \
    apt-get install -y --no-install-recommends software-properties-common && \
    add-apt-repository ppa:oisf/suricata-stable -y && \
    apt-get update && \
    apt-get install -y suricata \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /var/cache/apt/archives/* \
    && rm -rf /tmp/*

# Verify Suricata version and installation
RUN echo "Verifying Suricata 8.x installation..." && \
    dpkg -l | grep suricata && \
    which suricata && \
    ls -la /usr/bin/suricata && \
    dpkg-query -W -f='${Package} ${Version}\n' suricata

# Install Python packages for ML analysis using system package manager
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3-pandas \
    python3-numpy \
    python3-sklearn \
    python3-tz \
    python3-dateutil \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create directories for logs and scripts
RUN mkdir -p /logs /scripts /captures /analysis /var/log/suricata

# Configure Suricata
COPY suricata.yaml /etc/suricata/suricata.yaml
RUN mkdir -p /etc/suricata/rules && \
    touch /etc/suricata/rules/suricata.rules && \
    mkdir -p /var/lib/suricata/rules

# Copy monitoring scripts
COPY start_suricata_monitoring.sh /
COPY scripts/ /scripts/
COPY healthcheck.sh /usr/local/bin/
RUN chmod +x /start_suricata_monitoring.sh /usr/local/bin/healthcheck.sh

# Configure log rotation
COPY logrotate.conf /etc/logrotate.d/testbed

# Working directory
WORKDIR /scripts

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD /usr/local/bin/healthcheck.sh

# Security labels
LABEL maintainer="Security Testbed Team" \
      version="3.0" \
      description="Educational security testing container - Suricata 8.x IDS monitoring" \
      suricata.version="8.x" \
      security.level="educational" \
      usage="isolated-environment-only"

# Default command
# CMD ["/start_suricata_monitoring.sh"]