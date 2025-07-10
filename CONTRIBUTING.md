# Contributing to Security Testbed

First off, thank you for considering contributing to the Security Testbed! 🎉

## Table of Contents
- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Security Guidelines](#security-guidelines)

## Code of Conduct

This project adheres to a code of conduct that promotes a welcoming and inclusive environment. By participating, you are expected to uphold this code.

### Our Standards
- Use welcoming and inclusive language
- Be respectful of differing viewpoints and experiences
- Gracefully accept constructive criticism
- Focus on what is best for the community
- Show empathy towards other community members

## How Can I Contribute?

### Reporting Bugs
- Use the GitHub Issues with the bug report template
- Include detailed information about your environment
- Provide clear steps to reproduce the issue
- Include relevant logs and error messages

### Suggesting Features
- Use the GitHub Issues with the feature request template
- Clearly describe the feature and its benefits
- Consider the educational/research focus of the project

### Contributing Code

#### Types of Contributions Welcome:
- **Attack Scenarios**: New attack vectors and techniques
- **Monitoring Tools**: Enhanced traffic analysis and detection
- **Documentation**: Improvements to setup guides and tutorials
- **Infrastructure**: Docker, networking, and automation improvements
- **Security Enhancements**: Better isolation and safety features

## Development Setup

### Prerequisites
- Docker Engine 20.10+
- Docker Compose v2
- Linux host (for OVS networking)
- At least 4GB RAM and 10GB disk space

### Local Development
```bash
# Clone the repository
git clone <your-fork>
cd sec-testbed

# Test your changes
./utils/test_build.sh

# Start the testbed
./start_testbed.sh

# Run tests
./utils/status.sh
```

### Running Tests
```bash
# Lint shell scripts
find . -name "*.sh" -exec shellcheck {} \;

# Validate Docker configurations
docker compose config

# Test container builds
./utils/test_build.sh

# Full integration test
./start_testbed.sh && ./utils/cleanup.sh
```

## Pull Request Process

1. **Fork** the repository
2. **Create** a feature branch from `main`
3. **Make** your changes following coding standards
4. **Test** your changes thoroughly
5. **Update** documentation if needed
6. **Submit** a pull request

### PR Requirements
- [ ] Code follows project coding standards
- [ ] All tests pass
- [ ] Documentation is updated
- [ ] Commit messages are clear and descriptive
- [ ] Security considerations are addressed

### PR Template
When submitting a PR, please include:
- **Description**: What does this PR do?
- **Motivation**: Why is this change needed?
- **Testing**: How was this tested?
- **Security**: Any security implications?
- **Documentation**: What documentation was updated?

## Coding Standards

### Shell Scripts
- Use `#!/bin/bash` shebang
- Include `set -euo pipefail` for error handling
- Use meaningful variable names
- Add comments for complex logic
- Follow [Google Shell Style Guide](https://google.github.io/styleguide/shellguide.html)

### Docker
- Use multi-stage builds when appropriate
- Minimize image size and layers
- Use specific base image versions
- Include health checks where relevant
- Follow security best practices

### Documentation
- Use clear, concise language
- Include practical examples
- Keep security warnings prominent
- Update README for any user-facing changes

## Security Guidelines

⚠️ **Critical Security Considerations**

### Development Safety
- **Never expose vulnerable services to public networks**
- **Always test in isolated environments**
- **Use VM or container isolation for development**
- **Regularly update base images and dependencies**

### Code Review Focus
- Ensure no real credentials are hardcoded
- Verify isolation mechanisms are maintained
- Check that attack tools cannot escape containment
- Validate that monitoring doesn't expose sensitive data

### Responsible Disclosure
- If you discover security issues in the isolation mechanisms, please report privately first
- For educational vulnerabilities (intended behavior), use normal issue reporting

## Commit Messages

Follow conventional commit format:
```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes
- `refactor`: Code refactoring
- `test`: Test additions/changes
- `chore`: Maintenance tasks

**Examples:**
```
feat(attacker): add new SQL injection scenarios
fix(network): resolve OVS bridge configuration issue
docs(readme): update installation requirements
```

## Getting Help

- **Documentation**: Check the [README](README.md) and [docs/](docs/) directory
- **Issues**: Search existing issues before creating new ones
- **Discussions**: Use GitHub Discussions for questions and ideas

## Recognition

Contributors will be recognized in:
- Project README contributors section
- Release notes for significant contributions
- Special acknowledgments for security improvements

Thank you for contributing to the Security Testbed project! 🚀
