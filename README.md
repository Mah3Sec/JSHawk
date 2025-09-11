# JSHawk - Advanced JavaScript Security Scanner

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Bash](https://img.shields.io/badge/Language-Bash-green.svg)](https://www.gnu.org/software/bash/)
[![Version](https://img.shields.io/badge/Version-1.1-blue.svg)](https://github.com/Mah3Sec/JSHawk/releases/latest)

**JSHawk** is a powerful, context-aware JavaScript security scanner with source map support that hunts for exposed credentials, API keys, and sensitive information in both minified JavaScript files and their original source code.

## Latest Update - v1.1

**NEW: Source Map Support Added!**
- Automatically discovers and analyzes JavaScript source maps
- Extracts secrets from original unminified source code  
- Enhanced detection of credentials hidden in readable code
- [Download v1.1](https://github.com/Mah3Sec/JSHawk/releases/latest)

## Features

### Context-Aware Detection
- **Smart Pattern Matching**: Only flags credentials that appear in proper configuration context
- **False Positive Reduction**: Advanced filtering to minimize noise
- **Multi-Pattern Support**: Detects 20+ credential types with high accuracy

### Advanced Capabilities
- **Custom Regex Support**: Add your own detection patterns
- **Parallel Processing**: Multi-threaded downloads for speed
- **Organized Results**: Clean directory structure with detailed reports
- **Comprehensive Coverage**: Discovers JS files through multiple methods

### Source Map Analysis
- **Automatic Discovery**: Finds .js.map files for every JavaScript file
- **Inline Source Map Extraction**: Decodes base64 encoded source maps
- **Original Code Analysis**: Analyzes unminified source code for better detection
- **Enhanced Pattern Matching**: More effective on readable variable names and comments

## Why Source Maps Matter

Source maps are files that map minified JavaScript back to original source code. They often contain:
- **Original variable names** instead of minified `a`, `b`, `c`
- **Developer comments** with TODOs and potential credentials  
- **Readable code structure** for better pattern matching
- **Internal configurations** accidentally exposed

JSHawk automatically discovers and analyzes both external `.js.map` files and inline base64-encoded source maps embedded in JavaScript files.

## Supported Credential Types

### Cloud & Infrastructure
- AWS Access Keys (AKIA pattern)
- AWS Secret Keys (40-char base64)
- Google API Keys (AIza pattern)
- Azure Storage Keys
- Firebase Database URLs

### Development & CI/CD
- GitHub Personal Access Tokens
- GitLab Access Tokens
- Jenkins API Tokens

### Communication & Payment
- Slack Bot Tokens (xoxb, xoxa, xoxp, xoxr)
- Stripe Live Keys (sk_live, pk_live)
- SendGrid API Keys
- Twilio Account SID/Auth Tokens

### Database & Security
- Database Connection Strings (MySQL, PostgreSQL, MongoDB, Redis)
- JWT Secrets
- Private SSH/TLS Keys
- Generic API Keys (with context validation)

### Custom Patterns
- User-defined regex patterns
- Flexible pattern management
- Custom descriptions and categorization

## Installation

### Latest Release (Recommended)
```bash
# Download latest version
curl -L https://github.com/Mah3Sec/JSHawk/releases/latest/download/JSHawk.sh -o JSHawk.sh
chmod +x JSHawk.sh
```

### Development Version
```bash
# Clone the repository
git clone https://github.com/Mah3Sec/JSHawk.git
cd JSHawk
chmod +x JSHawk.sh

# Optional: Add to PATH
sudo cp JSHawk.sh /usr/local/bin/JSHawk
```

## Usage

### Basic Scan
```bash
./JSHawk.sh example.com
```

### Advanced Options
```bash
# Scan with subdomain list
./JSHawk.sh example.com --subdomains subdomains.txt

# Custom output directory
./JSHawk.sh example.com --output my_results

# Verbose mode with custom threads
./JSHawk.sh example.com --verbose --threads 20

# Add custom regex patterns
./JSHawk.sh example.com --custom-regex
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-s, --subdomains <file>` | Use subdomain list from file |
| `-c, --custom-regex` | Add custom regex patterns interactively |
| `-l, --list-patterns` | List all available detection patterns |
| `-o, --output <dir>` | Custom output directory |
| `-t, --threads <num>` | Number of concurrent downloads (default: 10) |
| `-v, --verbose` | Enable verbose output |
| `-h, --help` | Show help message |

## Custom Patterns

JSHawk supports custom regex patterns for organization-specific credentials:

### Adding Custom Patterns
```bash
# Interactive setup
./JSHawk.sh --custom-regex

# Manual configuration
echo "CUSTOM_API|secret_key_[a-zA-Z0-9]{32}|Custom API Key Pattern" >> ~/.jshawk/custom_patterns.txt
```

### Pattern Format
```
PATTERN_NAME|regex_pattern|description
```

### Examples
```
ACME_API|acme_[a-zA-Z0-9]{24}|ACME Corporation API Keys
INTERNAL_TOKEN|int_tok_[0-9a-f]{40}|Internal Service Tokens
LEGACY_KEY|legacy_[A-Z0-9]{16}|Legacy System Keys
```

## Output Structure

JSHawk creates an organized results directory:

```
jshawk_results/
├── example.com_20241201_143022/
│   ├── js_files/                    # Downloaded JavaScript files
│   │   ├── js_file_0001.js         # Regular JS files
│   │   ├── sourcemap_0001.js.map   # Source map files
│   │   └── inline_sourcemap_*.map  # Extracted inline source maps
│   ├── findings/
│   │   ├── secrets.txt             # Raw findings (CSV format)
│   │   ├── sourcemap_secrets.txt   # Source map specific findings
│   │   └── summary.txt             # Executive summary
│   ├── reports/
│   │   └── detailed_analysis.txt   # Comprehensive analysis
│   ├── logs/                       # Scan logs
│   ├── scan_info.txt              # Scan metadata
│   └── jshawk_final_report.txt    # Final comprehensive report
```

## Sample Output

```bash
JSHawk - Advanced JavaScript Security Scanner
═══════════════════════════════════════════════

[DISCOVERY] Processing: https://example.com
[SUCCESS] Downloaded 15,234 bytes
[FOUND] 12 unique JS files

[SOURCEMAP] Discovering source maps for: https://example.com
[SOURCEMAP-FOUND] 8 potential source map files

[DOWNLOAD] Starting parallel downloads (threads: 10)...
[DOWNLOAD COMPLETE] Success: 8, Failed: 4
[SOURCEMAP-SUCCESS] sourcemap_0001.js.map (45,123 bytes)
[INLINE-SUCCESS] Extracted from js_file_0003.js

[ANALYZE] Enhanced credential detection...
[AWS-ACCESS] AKIAIOSFODNN7EXAMPLE
[GITHUB] ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
[SOURCEMAP-SECRETS] Found 2 secrets in source maps!
[SOURCEMAP_AWS-ACCESS] AKIAIOSFODNN7EXAMPLE
[SOURCEMAP_GITHUB] ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

╔══════════════════════════════════════════════════════════════╗
║                  JSHAWK SCAN COMPLETE                        ║
╚══════════════════════════════════════════════════════════════╝

SECURITY ALERT: 5 potential security issues detected!
(2 from source maps)

Top Findings:
  [AWS_ACCESS_KEY] AKIAIOSFODNN7EXAMPLE
  [GITHUB_TOKEN] ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
  [SOURCEMAP_AWS_ACCESS_KEY] AKIAIOSFODNN7EXAMPLE
```

## Security Risk Assessment

JSHawk categorizes findings by risk level:

- **CRITICAL**: AWS keys, Stripe live keys, database URLs, private keys
- **HIGH**: GitHub tokens, Google API keys, Slack tokens
- **MEDIUM**: Generic API keys, JWT secrets
- **CUSTOM**: User-defined patterns
- **SOURCE MAP**: Findings specifically from source map analysis

## Configuration

### User Configuration Directory
JSHawk stores configuration in `~/.jshawk/`:
- `custom_patterns.txt`: Custom regex patterns
- Configuration files and user preferences

### Environment Variables
```bash
export JSHAWK_THREADS=20          # Default thread count
export JSHAWK_TIMEOUT=30          # Download timeout
export JSHAWK_OUTPUT_DIR="./scans" # Default output directory
```

## Contributing

We welcome contributions! Here's how you can help:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Add your changes**
4. **Write tests** (if applicable)
5. **Commit your changes**: `git commit -m 'Add amazing feature'`
6. **Push to branch**: `git push origin feature/amazing-feature`
7. **Open a Pull Request**

### Contributing Ideas
- New credential detection patterns
- Source map parsing improvements
- Performance optimizations
- Additional output formats (JSON, XML)
- Integration with security tools
- Docker support
- CI/CD pipeline integration

## Bug Reports

Found a bug? Please create an issue with:
- JSHawk version
- Operating system
- Command used
- Expected vs actual behavior
- Sample output (sanitized)

## Advanced Usage

### Batch Scanning
```bash
# Scan multiple domains
echo -e "example.com\ntest.com\ndemo.com" | while read domain; do
    ./JSHawk.sh "$domain" --output "batch_scan_$(date +%Y%m%d)"
done
```

### Integration with Other Tools
```bash
# Combine with subfinder
subfinder -d example.com | ./JSHawk.sh example.com --subdomains /dev/stdin

# Parse results
cat results/findings/secrets.txt | grep "AWS_" | cut -d'|' -f2

# Check for source map findings specifically
grep "SOURCEMAP_" results/findings/secrets.txt
```

### Automation Examples
```bash
# Daily security scan
0 2 * * * /usr/local/bin/JSHawk example.com --output /var/security/daily_scans/

# CI/CD Integration
./JSHawk.sh $CI_COMMIT_REF_NAME.staging.example.com --output security_scan
if [ -s security_scan/findings/secrets.txt ]; then
    echo "Security issues found, failing build"
    exit 1
fi
```

## Updating from v1.0

If you're using JSHawk v1.0, update to v1.1 for source map support:

```bash
# Backup current version
cp JSHawk.sh JSHawk_v1.0_backup.sh

# Download latest version
curl -L https://github.com/Mah3Sec/JSHawk/releases/latest/download/JSHawk.sh -o JSHawk.sh
chmod +x JSHawk.sh

# Verify version
./JSHawk.sh --help | grep "v1.1"
```

## Legal Disclaimer

**JSHawk is intended for authorized security testing only.**

- Only scan domains you own or have explicit permission to test
- Respect rate limits and terms of service
- Use responsibly and ethically
- The authors are not responsible for misuse

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by various security research tools
- Built for the security community
- Thanks to all contributors and users

## Support

- **Issues**: [GitHub Issues](https://github.com/Mah3Sec/jshawk/issues)
- **Twitter**: [@mah3sec](https://twitter.com/mah3sec)

---

**Made with ❤️ for the security community**

*Hunt smarter, not harder*
