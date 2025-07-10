# Multi-stage build for security testbed monitor container
FROM ubuntu:22.04 AS base

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Install network monitoring and analysis tools
RUN echo 'APT::Install-Recommends "0";' | tee -a /etc/apt/apt.conf.d/01norecommends && \
    echo 'APT::Install-Suggests "0";' | tee -a /etc/apt/apt.conf.d/01norecommends && \
    echo 'Acquire::ForceIPv4=true;' | tee -a /etc/apt/apt.conf.d/99force-ipv4 && \
    apt-get update && apt-get install -y --no-install-recommends \
    # Traffic capture tools
    tcpdump \
    tshark \
    # Flow analysis tools
    argus-client \
    argus-server \
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
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /var/cache/apt/archives/* \
    && rm -rf /tmp/*

# Create non-root user for better security
RUN groupadd -r monitor && useradd -r -g monitor -d /home/monitor -s /bin/bash monitor \
    && mkdir -p /home/monitor \
    && chown -R monitor:monitor /home/monitor

# Install Python packages for traffic analysis
RUN pip3 install --no-cache-dir --upgrade pip \
    && pip3 install --no-cache-dir \
    scapy \
    pandas \
    numpy \
    dpkt \
    pyshark

# Create directories for logs and scripts
RUN mkdir -p /logs /analysis_scripts /captures /analysis 

# Copy monitoring scripts
COPY start_monitoring.sh /
RUN chmod +x /start_monitoring.sh

# Configure log rotation
COPY logrotate.conf /etc/logrotate.d/testbed

# Working directory
WORKDIR /analysis_scripts

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD /usr/local/bin/healthcheck.sh

# Security labels
LABEL maintainer="Security Testbed Team" \
      version="1.0" \
      description="Educational security testing container - Network monitoring" \
      security.level="educational" \
      usage="isolated-environment-only"