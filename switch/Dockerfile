# Multi-stage build for security testbed switch container
FROM ubuntu:24.04 AS base

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Install Open vSwitch, Docker client, and related tools
RUN echo 'APT::Install-Recommends "0";' | tee -a /etc/apt/apt.conf.d/01norecommend && \
    echo 'APT::Install-Suggests "0";' | tee -a /etc/apt/apt.conf.d/01norecommend && \
    echo 'Acquire::ForceIPv4=true;' | tee -a /etc/apt/apt.conf.d/99force-ipv4 && \
    apt-get update && apt-get install -y --no-install-recommends \
    openvswitch-switch \
    openvswitch-common \
    openvswitch-pki \
    openvswitch-testcontroller \
    bridge-utils \
    net-tools \
    iputils-ping \
    iproute2 \
    tcpdump \
    iptables \
    util-linux \
    curl \
    ca-certificates \
    gnupg \
    lsb-release \
    vim \
    nano \
    procps \
    lsof \
    && curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null \
    && apt-get update \
    && apt-get install -y --no-install-recommends docker-ce-cli \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /var/cache/apt/archives/* \
    && rm -rf /tmp/*

# Create directories
RUN mkdir -p /logs

# Copy configuration scripts
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh

# Security labels
LABEL maintainer="Security Testbed Team" \
      version="1.0" \
      description="Educational security testing container - OVS Switch" \
      security.level="educational" \
      usage="isolated-environment-only" \
      network.mode="host" \
      privileges.required="true"

# Production stage
FROM base AS production

ENTRYPOINT ["/entrypoint.sh"]