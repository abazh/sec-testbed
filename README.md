# Security Testbed - Research Environment

> **⚠️ CRITICAL WARNING**: This testbed contains intentionally vulnerable services. Use ONLY in isolated environments for educational and research purposes.

## Overview

A modernized Docker-based security testbed for generating high-quality cybersecurity datasets for ML/AI research. Features enhanced attack correlation, improved monitoring, and comprehensive analysis capabilities.

### Key Features
- Dataset generation with attack correlation and timing markers
- Automated attack orchestration and labeling
- Comprehensive monitoring: full packet capture and flow analysis
- Health monitoring: container health checks and service validation
- Resource management: optimized container resource allocation

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Attacker      │    │      OvS        │    │     Victim      │
│  100.64.0.10    │────│   100.64.0.1    │────│  100.64.0.20    │
│                 │    │   (ovs-br0)     │    │                 │
│ • Attack Tools  │    │                 │    │ • WordPress     │
│ • Correlation   │    │                 │    │ • Vuln Services │
└─────────────────┘    └────────┬────────┘    └─────────────────┘
                                │
                                │ (port-mirrored traffic)
                      ┌─────────┴─────────┐
                      │      Monitor      │
                      │   100.64.0.30     │
                      │                   │
                      │ • Traffic Capture │
                      │ • Flow Analysis   │
                      │ • Dataset Gen     │
                      └───────────────────┘
```

## Quick Start

```bash
# 1. Clone and setup
git clone <repository>
cd sec-testbed

# 2. Start testbed
./start_testbed.sh
or 
make start

# 3. Check status
./utils/status.sh
or
make status

# 4. Run attacks (automated)
docker compose exec attacker bash
./attack_scenarios/attack_tools.sh --automated
or
make attack-automated

# 5. Generate dataset
docker compose exec monitor python3 /scripts/dataset_generator.py
or 
make generate-dataset

# 6. Clean up or Reset
make clean
or
make reset
```

## Components

### 1. **Attacker Container** (100.64.0.10)
- **Tools**: nmap, sqlmap, hydra, hping3, dirb, nikto
- **Features**: 
  - Attack orchestration with `attack_tools.sh`
  - Logging and correlation markers
  - Configurable attack timing and retries

### 2. **Victim Container** (100.64.0.20)
- **Services**:
  - WordPress (port 80) with intentional vulnerabilities
  - Vulnerable login page (`/vulnerable_login.php`)
  - MySQL database with weak credentials
- **Features**:
  - Health monitoring and service validation
  - Persistent data volumes
  - Enhanced logging and monitoring

### 3. **Monitor Container** (100.64.0.30)
- **Capabilities**:
  - Full packet capture with tcpdump
  - Flow analysis with Argus
  - Dataset generation
  - Attack correlation and labeling

### 4. **Switch Container** (Host Network)
- **Features**:
  - OpenVSwitch with port mirroring
  - Enhanced health monitoring
  - Graceful shutdown handling
  - Network isolation and security

## Management Commands

```bash
make help              # Show all available commands
make start             # Start the testbed
make status            # Check detailed status
make attack-automated  # Run all attacks
make generate-dataset  # Create ML dataset
make clean             # Clean up resources

# Direct script usage
./start_testbed.sh     # Startup script
./utils/status.sh      # Status check
```

## Attack Scenarios


The attack tools support multiple execution modes:

```bash
# Interactive mode
docker compose exec attacker bash
./attack_scenarios/attack_tools.sh --interactive

# Automated sequence
docker compose exec attacker bash
./attack_scenarios/attack_tools.sh --automated

# Single attack
docker compose exec attacker bash
./attack_scenarios/attack_tools.sh --attack nmap
```

### Available Attacks:
- **Network Scan**: Comprehensive nmap reconnaissance
- **SYN Flood**: DDoS attack simulation
- **SQL Injection**: Automated vulnerability testing
- **WordPress Brute Force**: Authentication bypass attempts
- **Directory Enumeration**: Web application discovery

## Dataset Generation


Dataset generation:

```bash
# Generate dataset
docker compose exec monitor python3 /scripts/dataset_generator.py
```

**Note:** Output is typically written to `data/analysis/` as logs or CSV, depending on script configuration. Check the script and output directory for available formats.

---

**Version**: 1.0  
**Compatibility**: Docker 20.10+, Docker Compose 2.0+
  ```
- Each log ends with a summary line for easy interpretation.
- Marker logs now include attack descriptions for context.

### Step 3: Generate and Check Datasets
- Datasets are generated automatically by the monitor container after attacks.
- View datasets and reports:

  ```bash
  ls data/analysis/
  head data/analysis/*.csv  # If CSVs are generated
  cat data/analysis/*.log   # For logs
  ```
# Attack markers allow you to correlate attacks with network flows in the dataset.

### Step 4: Troubleshooting Tips
- If you see 'no such file or directory' errors, check the script path (`/attack_scenarios/attack_tools.sh`).
- If logs or datasets are missing, ensure all containers are healthy and attacks were executed.
- For connectivity issues, verify port mirroring and container IPs as described above.

---

**Educational Use Only** - This testbed is designed for cybersecurity research and education in controlled environments.
