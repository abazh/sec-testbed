# Multi-stage build for security testbed monitor container
FROM debian:bookworm-slim AS build


# Set environment variables for non-interactive install and Argus versions
ENV DEBIAN_FRONTEND=noninteractive \
    ARGUS_VERSION=5.0.2 \
    CLIENTS_VERSION=5.0.0 \
    TZ=UTC \
    PYTHONUNBUFFERED=1 \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

# Install build dependencies
RUN apt-get update && \
    apt-get install -y gcc make flex bison zlib1g-dev libpcap-dev wget \
    python3 python3-pip python3-venv python3-dev build-essential \
    ca-certificates curl tcpdump tshark ngrep net-tools iputils-ping iproute2 vim nano cron iftop nethogs procps inotify-tools && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /argus

# Download and extract source code from GitHub releases
RUN wget https://github.com/openargus/clients/archive/refs/tags/v${CLIENTS_VERSION}.tar.gz -O clients-${CLIENTS_VERSION}.tar.gz && \
    tar -xvf clients-${CLIENTS_VERSION}.tar.gz && \
    wget https://github.com/openargus/argus/archive/refs/tags/v${ARGUS_VERSION}.tar.gz -O argus-${ARGUS_VERSION}.tar.gz && \
    tar -xvf argus-${ARGUS_VERSION}.tar.gz

# Build and install Argus clients
RUN cd clients-${CLIENTS_VERSION} && \
    LIBS="-lz" ./configure && \
    make && \
    make install

# Build and install Argus server
RUN cd argus-${ARGUS_VERSION} && \
    LIBS="-lz" ./configure && \
    make && \
    make install

# Runtime stage
FROM debian:bookworm-slim AS runtime

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y zlib1g libpcap0.8 libtirpc3 python3 python3-pip python3-venv python3-dev build-essential \
    ca-certificates curl tcpdump tshark ngrep net-tools iputils-ping iproute2 vim nano cron iftop nethogs procps inotify-tools && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Create non-root user for better security
RUN groupadd -r monitor && useradd -r -g monitor -d /home/monitor -s /bin/bash monitor \
    && mkdir -p /home/monitor \
    && chown -R monitor:monitor /home/monitor

# Install Python packages for traffic analysis
RUN pip3 install --break-system-packages --no-cache-dir \
    scapy \
    pandas \
    numpy \
    dpkt \
    pyshark

RUN mkdir -p /logs /scripts /captures /analysis /data/attacker_logs

# Copy Argus and clients from build stage
COPY --from=build /usr/local /usr/local

# Copy monitoring scripts
COPY start_monitoring.sh /
COPY scripts/ /scripts/
COPY healthcheck.sh /usr/local/bin/
RUN chmod +x /start_monitoring.sh /usr/local/bin/healthcheck.sh

# Configure log rotation
COPY logrotate.conf /etc/logrotate.d/testbed

# Working directory
WORKDIR /scripts

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD /usr/local/bin/healthcheck.sh

# Security labels
LABEL maintainer="Security Testbed Team" \
      version="1.0" \
      description="Educational security testing container - Network monitoring" \
      security.level="educational" \
      usage="isolated-environment-only"

# Set default command
CMD ["/start_monitoring.sh"]