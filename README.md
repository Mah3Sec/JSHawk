<div align="center">

```
     ██╗███████╗██╗  ██╗ █████╗ ██╗    ██╗██╗  ██╗
     ██║██╔════╝██║  ██║██╔══██╗██║    ██║██║ ██╔╝
     ██║███████╗███████║███████║██║ █╗ ██║█████╔╝
██   ██║╚════██║██╔══██║██╔══██║██║███╗██║██╔═██╗
╚█████╔╝███████║██║  ██║██║  ██║╚███╔███╔╝██║  ██╗
 ╚════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝
```

**JavaScript Secret Scanner · v3.0**

[![Bash](https://img.shields.io/badge/Shell-Bash-green?style=flat-square)](https://www.gnu.org/software/bash/)
[![License](https://img.shields.io/badge/License-MIT-red?style=flat-square)](LICENSE)
[![Author](https://img.shields.io/badge/Author-@Mah3Sec-CC0000?style=flat-square)](https://github.com/Mah3Sec)

*Context-aware credential detection · Entropy scoring · JS chain discovery · Endpoint probing · SARIF/HTML/Nuclei output*

</div>

---

## What is JSHawk?

JSHawk is an advanced JavaScript security scanner for bug bounty hunters and penetration testers. It downloads and deeply analyzes JavaScript files from a target domain, detecting exposed credentials, API keys, database URLs, private keys, and other secrets using 60+ patterns with Shannon entropy scoring to eliminate false positives.

**Two tools, one mission:**

| Tool | Description |
|---|---|
| `JSHawk.sh` | Bash CLI — deep recon, Wayback, source maps, endpoint probing |
| Browser Extension (In Review) | Real-time passive scanning as you browse, with endpoint probing |

---

## Features we offer

### JS Chain Discovery
When JSHawk fetches `app.js` and finds `/beam.js`, `/chunk.abc.js`, or `import('./auth')` inside it — it **automatically fetches and scans those too**, recursively, up to 3 levels deep. Webpack chunk manifests are parsed to reconstruct all lazy-loaded module URLs. Most tools only scan the JS files linked directly from HTML.

### Context-Aware Scoring
Every finding is scored not just by entropy, but by its **surrounding code context**. A secret inside a `config = { ... }` block or `production` environment object is rated `critical`. The same value inside a comment tagged `// example` or `// TODO` is suppressed. No other open-source JS scanner does context scoring.

### Endpoint Probing with Session Auth
JSHawk extracts API routes from JS (`/api/v1/users`, `/graphql`, `fetch('/admin/...')`) and **fetches each one using your actual session cookies**, then scans the JSON responses for leaked secrets. Authenticated endpoints that return real data get scanned — not just the JS source.

### Diff Mode — Only New Findings
`--diff` compares current scan against `~/.jshawk/fingerprints.db` (SHA-256 hashes of all previously seen secrets) and **only reports secrets it has never seen before**. Essential for daily CI/CD scanning without alert fatigue.

### False Positive Management
`--fp-add <value>` permanently marks a value as a known-safe false positive. It is silently suppressed in every future scan, forever. Maintain your own per-company exclusion list.

### SARIF 2.1.0 Output
Structured results in SARIF format — plug directly into **GitHub Code Scanning**, **GitLab SAST**, or any SARIF-compatible CI pipeline. No glue code needed.

### HTML Report
Self-contained single-file HTML report with dark theme, sortable findings table, entropy scores, and clickable source URLs. Share with clients or include in pentest reports.

### Nuclei Template Export
Every finding becomes a **ready-to-use Nuclei template YAML** targeting the specific pattern that was found. Feed them straight into `nuclei -t jshawk_results/nuclei/` to re-verify at scale.

---

## Installation

```bash
# Clone
git clone https://github.com/Mah3Sec/JSHawk.git
cd JSHawk

# Make executable
chmod +x JSHawk.sh

# Optional: install globally
sudo ln -s "$(pwd)/JSHawk.sh" /usr/local/bin/jshawk

# Verify
jshawk --help
```

**Dependencies:** `bash`, `curl`, `python3` (for source maps + HTML report), `awk`, `grep`

---

## Quick Start

```bash
# Basic scan
jshawk target.com

# Full recon — Wayback + source maps + live validation + HTML report
jshawk target.com --wayback --source-maps --validate --html

# CI/CD — only new findings, SARIF output, exit 1 if found
jshawk target.com --diff --sarif --quiet

# Bug bounty — subdomain list + scope control + wordlist for ffuf
jshawk target.com -s subdomains.txt --scope scope.txt --wordlist --threads 30

# Authenticated endpoint probing
jshawk target.com --probe-endpoints --probe-cookies cookies.txt

# Export everything for further tooling
jshawk target.com --nuclei --wordlist --format json
```

---

## All Flags

### Targeting
| Flag | Description |
|---|---|
| `<domain>` | Target domain or full URL |
| `-s, --subdomains FILE` | File of subdomains/URLs (one per line) |
| `--scope FILE` | Only scan URLs matching patterns in this file |

### Discovery
| Flag | Default | Description |
|---|---|---|
| `--deep-crawl` | on | Follow JS refs inside JS files (chain discovery) |
| `--chain-depth N` | 3 | How many levels deep to follow JS→JS refs |
| `--wayback` | off | Query Wayback Machine for historical JS snapshots |
| `--source-maps` | off | Download `.map` files and reconstruct original source |
| `--no-deep-crawl` | — | Disable chain discovery (faster) |

### Detection
| Flag | Default | Description |
|---|---|---|
| `-e, --entropy N` | 3.5 | Entropy threshold — below this = placeholder, skipped |
| `--context` | on | Context-aware scoring (suppresses test/example values) |
| `--no-context` | — | Report everything regardless of context |
| `-c, --custom-regex` | — | Add custom patterns interactively |
| `-l, --list-patterns` | — | List all built-in patterns |

### Endpoint Probing
| Flag | Description |
|---|---|
| `--probe-endpoints` | Fetch discovered API routes and scan responses |
| `--probe-cookies FILE` | Session cookies file for authenticated probing |
| `--probe-headers FILE` | Auth headers file (e.g. `Authorization: Bearer ...`) |

### Validation
| Flag | Description |
|---|---|
| `--validate` | Live-confirm findings via provider APIs (AWS, GitHub, Stripe, OpenAI) |

### Output
| Flag | Description |
|---|---|
| `-o, --output DIR` | Output directory (default: `jshawk_results/`) |
| `--format FORMAT` | `txt` \| `json` \| `both` \| `sarif` \| `html` |
| `--sarif` | SARIF 2.1.0 output for GitHub/GitLab CI |
| `--html` | Self-contained HTML report |
| `--wordlist` | Export discovered endpoints as wordlist |
| `--nuclei` | Export findings as Nuclei template YAML |
| `--silent` | Machine-readable output only |
| `-q, --quiet` | Suppress all non-finding output |
| `--no-color` | Disable colors (for log files) |
| `-v, --verbose` | Show context lines and debug info |

### Performance
| Flag | Default | Description |
|---|---|---|
| `-t, --threads N` | 15 | Parallel download threads |
| `--rate-limit MS` | 0 | Delay between requests in milliseconds |
| `--resume` | off | Resume an interrupted scan |

### Diff & False Positives
| Flag | Description |
|---|---|
| `--diff` | Only report findings not seen in previous scans |
| `--fp-add SECRET` | Mark a value as a false positive (suppressed forever) |
| `--fp-list` | List all known false positives |
| `--fp-clear` | Clear all false positives |

### Proxy & Auth
| Flag | Description |
|---|---|
| `--proxy URL` | HTTP/SOCKS5 proxy (e.g. Burp Suite: `http://127.0.0.1:8080`) |
| `--header "K: V"` | Add custom request header (repeatable) |
| `--insecure` | Disable TLS verification |

---

## Detection Patterns (60+)

| Category | Patterns |
|---|---|
| **Cloud** | AWS Access Key, AWS Secret Key, Google API Key, Azure Storage Key, Azure Connection String, Firebase URL + API Key, GCP Service Account, DigitalOcean Token, Heroku API Key |
| **VCS / CI-CD** | GitHub Token, GitHub PAT, GitLab Token, npm Token, Jenkins Token, Travis CI Token, CircleCI Token |
| **Payment** | Stripe Live Secret, Stripe Live Public, Stripe Restricted Key, PayPal Client, Braintree Key, Shopify Admin Token, Shopify API Secret, Square Access Token |
| **Communication** | Slack Bot/User/App Token, Slack Webhook, SendGrid Key, Twilio SID, Twilio Auth Token, Mailgun Key, Mailchimp Key, Discord Bot Token, Discord Webhook, Telegram Bot Token |
| **AI Providers** | OpenAI API Key, Anthropic API Key, HuggingFace Token, Replicate API Key |
| **Database** | Database URL (MySQL/Postgres/MongoDB/Redis/AMQP), Hardcoded DB Password |
| **Secrets** | JWT Token, JWT Secret, Private Key (PEM), SSH Private Key, Encryption Key, Hardcoded Password, Generic API Key, Generic Secret Key |
| **Network** | Internal IP (10.x/192.168.x/172.16-31.x), Private Subnet CIDR, Basic Auth in URL, S3 Bucket URL |
| **Auth** | Auth0 Client Secret, Okta API Token, OAuth Client Secret, Mapbox Token |
| **Monitoring** | Sentry DSN, Datadog API Key, New Relic License Key, Amplitude API Key |
| **Custom** | User-defined patterns via `--custom-regex` or `~/.jshawk/custom_patterns.txt` |

All patterns are gated by **Shannon entropy ≥ 3.5** (configurable) so placeholder values like `YOUR_KEY_HERE`, `xxxxxxxxxxxx`, `00000000000` are never reported.

---

## Output Structure

```
jshawk_results/target.com_20240415_143022/
├── scan_info.json              # Scan metadata
├── js_files/                   # All downloaded JS files
├── findings/
│   └── secrets.txt             # Pipe-delimited findings (TYPE|SECRET|FILE|URL|LINE|RISK|ENTROPY|CONTEXT)
├── endpoints/
│   ├── discovered_paths.txt    # All API routes found in JS
│   └── probe_results.txt       # HTTP status codes from endpoint probing
├── source_maps/                # Reconstructed original source files
├── reports/
│   ├── jshawk.json             # Structured JSON report
│   ├── jshawk.sarif            # SARIF 2.1.0 for CI/CD
│   ├── jshawk_report.html      # Self-contained HTML report
│   └── endpoints_wordlist.txt  # Endpoints for ffuf/dirsearch
├── nuclei/                     # Nuclei template YAML per finding
└── logs/                       # Download logs and debug info
```

---

## CI/CD Integration

```yaml
# GitHub Actions
- name: JSHawk JS Secret Scan
  run: |
    chmod +x JSHawk.sh
    ./JSHawk.sh ${{ env.TARGET }} --diff --sarif --quiet
  continue-on-error: true

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: jshawk_results/*/reports/jshawk.sarif
```

```bash
# GitLab CI
jshawk_scan:
  script:
    - jshawk $TARGET --diff --sarif --quiet
  artifacts:
    reports:
      sast: jshawk_results/*/reports/jshawk.sarif
```

**Exit codes:**
- `0` — Clean, no findings
- `1` — Findings detected
- `2` — Scan error

---

## Browser Extension

The JSHawk browser extension brings real-time secret scanning to Chrome and Firefox.

**Install:** Load unpacked from `extension/` folder in `chrome://extensions`

**Features:**
- Passive auto-scan — every JS file that loads gets scanned automatically
- On-demand SCAN button — deep scan all JS on the current page
- JS chain discovery — follows `/beam.js`, webpack chunks, lazy imports
- Endpoint probing — fetches API routes **with your session cookies**
- 65+ patterns with entropy scoring
- Custom signatures saved permanently
- Session-persistent findings (survive service worker restarts)
- SARIF/JSON export + one-click bug bounty Markdown reports

**Screenshots:**

| Findings | Endpoints | Patterns |
|---|---|---|
| Real-time critical/high/medium findings with source URLs | API routes with HTTP status + LEAKED badge | 65+ built-in patterns + custom regex editor |

---

## Compared to alternatives

| Feature | JSHawk v3 | SecretFinder | LinkFinder | truffleHog |
|---|---|---|---|---|
| JS chain discovery | ✅ 3 levels deep | ❌ | ❌ | ❌ |
| Context-aware scoring | ✅ | ❌ | ❌ | Partial |
| Endpoint probing | ✅ with auth | ❌ | ❌ | ❌ |
| Wayback Machine | ✅ | ❌ | ❌ | ❌ |
| Source map recon | ✅ | ❌ | ❌ | ❌ |
| Diff mode | ✅ | ❌ | ❌ | ✅ |
| SARIF output | ✅ | ❌ | ❌ | ✅ |
| HTML report | ✅ | ❌ | ❌ | ❌ |
| Nuclei export | ✅ | ❌ | ❌ | ❌ |
| False positive mgmt | ✅ | ❌ | ❌ | Partial |
| Browser extension | ✅ | ❌ | ❌ | ❌ |
| No Python req | ✅ (pure bash) | ❌ | ❌ | ❌ |

---

## Legal

For **authorized security testing only**. You are responsible for ensuring you have permission to test any system you scan. JSHawk is provided as-is for educational and professional security research purposes.

---

## Author

**Mahendra Purbia** ([@Mah3Sec](https://github.com/Mah3Sec))

If JSHawk helped you find a bug, a shoutout or a star is appreciated.

---

<div align="center">
<sub>Built for the community · MIT License</sub>
</div>
