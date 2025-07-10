# Security Testbed - Security Policy and Guidelines

## 🚨 CRITICAL SECURITY WARNING

**This testbed contains intentionally vulnerable services and should ONLY be used in completely isolated environments for educational and research purposes.**

## Security Architecture

### Isolation Requirements

#### ✅ Required Environment
- **Isolated Network**: Must be completely isolated from production networks
- **Air-Gapped Preferred**: Physical or virtual air-gap recommended
- **VM/Container Host**: Run on dedicated virtual machines or isolated container hosts
- **No Internet Access**: Vulnerable services must never be exposed to the internet

#### ❌ Never Use In
- Production environments
- Networks with access to sensitive data
- Shared development environments
- Cloud environments without proper isolation
- Networks connected to corporate infrastructure

### Container Security

#### Privilege Escalation Controls
- **Switch Container**: Requires privileged mode and host networking for OVS functionality
- **Monitor Container**: Needs NET_ADMIN and NET_RAW capabilities for packet capture
- **Attacker Container**: Limited to NET_ADMIN and SYS_ADMIN for network testing
- **Victim Container**: Minimal privileges, only NET_ADMIN for network configuration

#### Network Segmentation
```
┌─────────────────────────────────────┐
│          Host Network               │
│  ┌─────────────────────────────┐   │
│  │      Testbed Subnet         │   │
│  │    100.64.0.0/24           │   │
│  │                            │   │
│  │  ┌────┐ ┌────┐ ┌────┐     │   │
│  │  │ATK │ │VIC │ │MON │     │   │
│  │  └────┘ └────┘ └────┘     │   │
│  │           │                │   │
│  │       ┌───▼───┐           │   │
│  │       │  OVS  │           │   │
│  │       └───────┘           │   │
│  └─────────────────────────────┘   │
└─────────────────────────────────────┘
```

### Data Protection

#### Sensitive Data Handling
- **No Real Credentials**: All passwords are obviously fake/weak
- **Dummy Data Only**: Use only synthetic or dummy data
- **Capture Encryption**: Consider encrypting packet captures at rest
- **Log Sanitization**: Ensure logs don't contain real credentials

#### Data Retention
- **Automatic Cleanup**: Configured log rotation and capture cleanup
- **Manual Cleanup**: Use `utils/cleanup.sh` for thorough cleanup
- **Secure Deletion**: Use secure deletion tools for sensitive captures

### Vulnerability Management

#### Intentional Vulnerabilities
The following vulnerabilities are **intentionally included** for educational purposes:

##### Victim Container
- **Weak SSH Configuration**: Root login enabled, weak passwords
- **Vulnerable WordPress**: Outdated version with known vulnerabilities
- **Weak MySQL Configuration**: Default/weak passwords, remote root access
- **PHP Information Disclosure**: phpinfo() page exposed
- **Directory Traversal**: Potential file inclusion vulnerabilities

##### Network Configuration
- **Unencrypted Traffic**: All traffic flows in plaintext for analysis
- **No Authentication**: Services configured with minimal security
- **Weak Network Controls**: Minimal firewall rules

#### Security Monitoring
- **Continuous Monitoring**: Monitor for unexpected network connections
- **Resource Monitoring**: Watch for unusual resource consumption
- **Container Escape Detection**: Monitor for container escape attempts
- **Host System Monitoring**: Monitor host system for compromise indicators

### Access Controls

#### User Management
- **Principle of Least Privilege**: Users created with minimal required permissions
- **Non-Root Operations**: Analysis scripts run as non-root where possible
- **Capability Limiting**: Containers use minimal required capabilities

#### Container Access
```bash
# Safe access patterns
docker exec -it sec_attacker /bin/bash    # Attacker analysis
docker exec -it sec_victim /bin/bash      # Victim investigation
docker exec -it sec_monitor /bin/bash     # Monitor analysis
docker exec -it sec_switch /bin/bash      # Switch debugging

# Avoid direct host access
# Never: docker run --privileged --net=host --pid=host
```

### Incident Response

#### Container Compromise
1. **Immediate Isolation**: Stop affected containers
2. **Evidence Preservation**: Capture container state and logs
3. **Impact Assessment**: Check for host system compromise
4. **Clean Rebuild**: Rebuild from clean images

#### Host Compromise
1. **Complete Shutdown**: Stop all testbed containers
2. **Network Isolation**: Disconnect from all networks
3. **Forensic Imaging**: Preserve system state
4. **Clean Rebuild**: Rebuild host system from clean state

### Compliance and Legal

#### Educational Use Disclaimer
- **Educational Purpose Only**: This software is for educational and research use only
- **No Warranty**: Provided "AS IS" without warranty
- **User Responsibility**: Users responsible for compliance with local laws
- **Ethical Use**: Must be used ethically and responsibly

#### Legal Considerations
- **Authorization Required**: Only test systems you own or have explicit permission to test
- **Local Laws**: Comply with all applicable local, state, and federal laws
- **Institutional Policies**: Follow your organization's security and research policies

### Security Best Practices

#### Deployment Checklist
- [ ] Environment is completely isolated
- [ ] No production data is accessible
- [ ] Monitoring is configured
- [ ] Access is restricted to authorized users
- [ ] Legal authorization is obtained
- [ ] Incident response plan is in place

#### Regular Security Tasks
- [ ] Update base container images monthly
- [ ] Review access logs weekly
- [ ] Verify isolation quarterly
- [ ] Update documentation as needed
- [ ] Conduct security training for users

### Reporting Security Issues

#### Scope
- **In Scope**: Issues with isolation mechanisms, unintended vulnerabilities, container escape
- **Out of Scope**: Intentional vulnerabilities, expected weak configurations

#### Contact
- Use GitHub Issues for non-security bugs
- Email [security@example.com] for security-related issues
- Include: Impact assessment, reproduction steps, proposed solutions

### Security Tools Integration

#### Scanning and Monitoring
```bash
# Container vulnerability scanning
trivy image sec-testbed_attacker
trivy image sec-testbed_victim
trivy image sec-testbed_monitor
trivy image sec-testbed_switch

# Runtime security monitoring
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy image --security-checks vuln,config

# Network monitoring
tcpdump -i ovs-br0 -w security_monitoring.pcap
```

#### Automated Security
- **CI/CD Integration**: Security scans in GitHub Actions
- **Dependency Checking**: Automated vulnerability scanning
- **Configuration Validation**: Docker and compose file validation
- **Secrets Scanning**: Ensure no real secrets in repository

---

## 🔒 Remember: Security is Everyone's Responsibility

This testbed is a powerful educational tool that requires responsible use. Always prioritize safety, isolation, and ethical considerations in your security research and education.

**Last Updated**: [DATE]
**Next Review**: [DATE + 3 months]
