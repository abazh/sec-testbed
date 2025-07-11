# Security Testbed - Streamlined Research Environment

> **⚠️ CRITICAL WARNING**: This testbed contains intentionally vulnerable services. Use ONLY in isolated environments for educational and research purposes.

## Overview

A simplified Docker-based security testbed for generating meaningful cybersecurity datasets. The environment consists of three core components connected through OpenVSwitch with port mirroring for comprehensive traffic analysis.

### Purpose
- **Dataset Generation**: Create labeled datasets for ML/AI security research
- **Attack Simulation**: Test various attack scenarios in controlled environment  
- **Network Monitoring**: Capture and analyze attack patterns with proper correlation
- **Security Research**: Evaluate detection algorithms and security tools

## Architecture

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Attacker  │    │     OvS     │    │   Victim    │
│ 100.64.0.10 │────│ 100.64.0.1  │────│ 100.64.0.20 │
└─────────────┘    └──────┬──────┘    └─────────────┘
                          │
                          │ (mirrored traffic)
                ┌─────────┴─────────┐
                │      Monitor      │
                │    100.64.0.30    │
                └───────────────────┘
```

## Components

### 1. **Attacker Container** (100.64.0.10)
- **Purpose**: Generate attack traffic with proper labeling
- **Tools**: nmap, sqlmap, hydra, hping3, dirb
- **Key Features**: 
  - Unified attack script (`attack_tools.sh`)
  - Attack timing markers for dataset correlation
  - Coordinated attack sequences

### 2. **Victim Container** (100.64.0.20:3000)
- **Purpose**: Host vulnerable services as attack targets
- **Services**:
  - OWASP Juice Shop (port 3000) - Modern vulnerable web application
- **Features**: Comprehensive web application security testing platform with multiple vulnerability categories

### 3. **Monitor Container** (100.64.0.30)
- **Purpose**: Capture and analyze all network traffic
- **Key Features**:
  - Full packet capture (tcpdump)
  - Flow analysis (Argus with all important features)
  - Attack correlation processor
  - Automated dataset generation

### 4. **Switch Container** (Host Network)
- **Purpose**: OpenVSwitch with port mirroring
- **Features**: Transparent traffic mirroring to monitor

## Quick Start

1. **Setup Environment**
   ```bash
   git clone <repository>
   cd sec-testbed
   ```

2. **Configure (Optional)**
   ```bash
   # Edit .env file if needed - defaults work for most cases
   nano .env
   ```

3. **Start Testbed**
   ```bash
   docker compose up -d
   ```

4. **Run Attacks**
   ```bash
   # Access attacker container
   docker compose exec -it attacker bash
   
   # Run attack tools
   ./attack_scenarios/attack_tools.sh
   ```

5. **Access Services**
   - Juice Shop: http://100.64.0.20:3000

6. **Monitor Results**
   ```bash
   # Check captures
   ls data/captures/
   
   # View generated datasets
   ls data/analysis/
   ```

## Attack Scenarios

The unified attack script provides:

1. **Network Reconnaissance** - Port scanning and service enumeration (port 3000)
2. **SQL Injection** - Automated SQLi testing on Juice Shop REST API endpoints
3. **Brute Force** - Juice Shop login attacks
4. **DDoS Simulation** - SYN flood and ICMP flood attacks targeting port 3000
5. **Directory Enumeration** - Web directory discovery on Juice Shop
6. **Coordinated Sequences** - Full attack chains with proper timing

## Dataset Generation

### Features Extracted
- **Flow-level**: Duration, packet count, byte count, flags, protocol
- **Behavioral**: Connection states, port patterns, timing analysis
- **Attack Correlation**: Precise timing correlation with attack markers

### Output Formats
- **CSV Dataset**: `security_dataset_YYYYMMDD_HHMMSS.csv`
- **Attack Subset**: `attacks_only_YYYYMMDD_HHMMSS.csv`
- **Analysis Report**: `analysis_report_YYYYMMDD_HHMMSS.json`

### Labels
- `normal` - Legitimate traffic
- `attack` - Malicious traffic with specific attack type classification

## Data Collection Directories

```
data/
├── captures/          # Raw packet captures (.pcap) and flows (.arg)
├── analysis/          # Generated datasets and reports  
├── attacker_logs/     # Attack execution logs and timing markers
├── victim_logs/       # Target service logs (Juice Shop)
└── switch_logs/       # Network switch logs
```

## Dependencies

- Docker & Docker Compose
- OpenVSwitch (installed in switch container)
- Linux host with network privileges

## Security Considerations

- **Isolation**: Always run in isolated networks
- **No Internet**: Never expose to public internet
- **Weak Credentials**: Intentionally vulnerable - for research only
- **Clean Up**: Stop containers when not in use

## Stopping the Testbed

```bash
docker compose down
```

## Research Applications

1. **Intrusion Detection**: Train ML models on labeled attack data
2. **Anomaly Detection**: Develop behavioral analysis algorithms  
3. **Threat Intelligence**: Study attack patterns and signatures
4. **Security Tool Testing**: Validate detection capabilities

## Troubleshooting

- **OVS Issues**: Check `docker logs sec_switch`
- **No Traffic**: Verify port mirroring with `ovs-vsctl list Mirror`
- **Service Access**: Confirm container IPs with `docker network inspect sec-testbed`

---

**Educational Use Only** - This testbed is designed for cybersecurity research and education in controlled environments.
