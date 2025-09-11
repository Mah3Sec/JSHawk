# 🦅 JSHawk Usage Examples

This document provides comprehensive examples of using JSHawk for various security testing scenarios.

## 📚 Table of Contents

- [Basic Usage](#basic-usage)
- [Advanced Scanning](#advanced-scanning)
- [Custom Patterns](#custom-patterns)
- [Automation & CI/CD](#automation--cicd)
- [Result Analysis](#result-analysis)
- [Integration Examples](#integration-examples)

## 🚀 Basic Usage

### Simple Domain Scan
```bash
# Basic scan of a single domain
./jshawk.sh example.com

# Scan with HTTPS URL
./jshawk.sh https://example.com

# Scan with custom port
./jshawk.sh https://example.com:8443
```

### Subdomain Scanning
```bash
# Create subdomain list
echo -e "api.example.com\nstaging.example.com\ndev.example.com" > subdomains.txt

# Scan with subdomain list
./jshawk.sh example.com --subdomains subdomains.txt

# Combine with subfinder
subfinder -d example.com -silent > subs.txt
./jshawk.sh example.com --subdomains subs.txt
```

## 🔧 Advanced Scanning

### Performance Tuning
```bash
# High-speed scan with 20 threads
./jshawk.sh example.com --threads 20

# Verbose output for debugging
./jshawk.sh example.com --verbose

# Custom output directory
./jshawk.sh example.com --output security_audit_2024
```

### Large-Scale Scanning
```bash
# Scan multiple domains in sequence
for domain in example.com test.com demo.com; do
    echo "Scanning $domain..."
    ./jshawk.sh "$domain" --output "batch_$(date +%Y%m%d)/$domain"
done

# Parallel domain scanning
echo -e "example.com\ntest.com\ndemo.com" | xargs -I {} -P 3 ./jshawk.sh {} --output parallel_scan/{}
```

## 🎨 Custom Patterns

### Adding Custom Regex Patterns

#### Interactive Setup
```bash
# Interactive pattern configuration
./jshawk.sh --custom-regex

# Follow prompts to add patterns:
# Pattern Name: ACME_API
# Regex Pattern: acme_[a-zA-Z0-9]{24}
# Description: ACME Corporation API Keys
```

#### Manual Configuration
```bash
# Direct file editing
echo "CUSTOM_SECRET|secret_[0-9a-f]{32}|Custom Secret Pattern" >> ~/.jshawk/custom_patterns.txt
echo "INTERNAL_KEY|internal_[A-Z0-9]{16}|Internal System Keys" >> ~/.jshawk/custom_patterns.txt
echo "API_TOKEN|tok_[a-zA-Z0-9_]{40}|API Token Pattern" >> ~/.jshawk/custom_patterns.txt
```

### Pattern Examples

#### Organization-Specific Patterns
```bash
# Company-specific API keys
COMPANY_API|mycompany_[a-zA-Z0-9]{32}|MyCompany API Keys

# Service-specific tokens
SERVICE_TOKEN|svc_[0-9a-f]{40}|Service Authentication Tokens

# Legacy system credentials
LEGACY_CRED|legacy_[A-Z0-9]{24}|Legacy System Credentials

# Internal service keys
INTERNAL_SVC|int_[a-zA-Z0-9_-]{36}|Internal Service Keys
```

#### Generic Useful Patterns
```bash
# JWT-like tokens
JWT_CUSTOM|ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|Custom JWT Tokens

# Base64 encoded secrets (32+ chars)
B64_SECRET|[A-Za-z0-9+/]{32,}={0,2}|Base64 Encoded Secrets

# Hex encoded keys (32+ chars)
HEX_KEY|[a-fA-F0-9]{32,}|Hexadecimal Keys

# UUID-like patterns
UUID_SECRET|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|UUID Secrets
```

## 🤖 Automation & CI/CD

### GitHub Actions Integration
```yaml
# .github/workflows/security-scan.yml
name: JSHawk Security Scan

on:
  push:
    branches: [ main, staging ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
    - name: Checkout code
      uses: actions/checkout@v3
      
    - name: Install JSHawk
      run: |
        curl -sSL https://raw.githubusercontent.com/yourusername/jshawk/main/install.sh | bash
        
    - name: Run Security Scan
      run:
