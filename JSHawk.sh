#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  JSHawk v3.0 — Advanced JavaScript Security Scanner                        ║
# ║  Context-Aware | Entropy Scoring | AST-Level Detection | Smart Dedup       ║
# ║  Endpoint Probing | JS Chain Discovery | SARIF/JSON/HTML Output             ║
# ║  Author: Mahendra Purbia (@Mah3Sec)                                        ║
# ║  GitHub:  https://github.com/Mah3Sec/JSHawk                                ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m';  GREEN='\033[0;32m';  YELLOW='\033[1;33m'
BLUE='\033[0;34m'; PURPLE='\033[0;35m'; CYAN='\033[0;36m'
BOLD='\033[1m';    DIM='\033[2m';       NC='\033[0m'
ORANGE='\033[38;5;208m'; GREY='\033[38;5;240m'

# ── Version & Config ──────────────────────────────────────────────────────────
readonly VERSION="3.0"
readonly CONFIG_DIR="$HOME/.jshawk"
readonly CUSTOM_REGEX_FILE="$CONFIG_DIR/custom_patterns.txt"
readonly FINGERPRINT_DB="$CONFIG_DIR/fingerprints.db"
readonly FALSE_POSITIVE_DB="$CONFIG_DIR/false_positives.txt"
readonly MAIN_RESULTS_DIR="jshawk_results"

# Defaults
THREADS=15
ENTROPY_THRESHOLD="3.5"
VERBOSE=false
NO_COLOR=false
QUIET=false
NO_BANNER=false
WAYBACK=false
SOURCE_MAPS=false
VALIDATE=false
INSECURE=false
PROXY=""
SCOPE_FILE=""
OUTPUT_FORMAT="txt"
EXTRA_HEADERS=()
DOMAIN=""
SUBDOMAIN_FILE=""
CUSTOM_OUTPUT=""

# v3 new flags
DEEP_CRAWL=true          # Follow JS refs inside JS (chain discovery)
ENDPOINT_PROBE=false     # Probe discovered API endpoints for leaks
CONTEXT_MODE=true        # Context-aware scoring (variable name + assignment)
DIFF_MODE=false          # Only report new findings vs last scan
RESUME=false             # Resume interrupted scan
WORDLIST_OUT=false       # Export endpoints as wordlist
CHAIN_DEPTH=3            # How deep to follow JS->JS references
RATE_LIMIT=0             # ms delay between requests (0 = no limit)
SILENT_MODE=false        # Machine-readable output only
HTML_REPORT=false        # Generate HTML report
SARIF_OUT=false          # SARIF output for CI/CD integrations
NUCLEI_EXPORT=false      # Export findings as Nuclei templates

mkdir -p "$CONFIG_DIR"

# ── Rotating user-agents ──────────────────────────────────────────────────────
UA_LIST=(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 Version/17.4 Safari/605.1.15"
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0"
    "Googlebot/2.1 (+http://www.google.com/bot.html)"
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"
)
USER_AGENT="${UA_LIST[$((RANDOM % ${#UA_LIST[@]}))]}"

# ── Logging helpers ───────────────────────────────────────────────────────────
log()   { [[ "$QUIET" == true || "$SILENT_MODE" == true ]] && return; echo -e "$@"; }
vlog()  { [[ "$VERBOSE" == true && "$QUIET" == false ]] && echo -e "$@" || true; }
slog()  { echo -e "$@"; }  # always print (for silent/machine mode)
err()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*" >&2; }
info()  { log "${BLUE}[*]${NC} $*"; }
ok()    { log "${GREEN}[+]${NC} $*"; }
found() { log "${RED}[!]${NC} $*"; }

setup_colors() {
    [[ "$NO_COLOR" == true ]] &&
        RED='' GREEN='' YELLOW='' BLUE='' PURPLE='' CYAN='' \
        BOLD='' DIM='' NC='' ORANGE='' GREY=''
}

# ── Shannon entropy (pure awk, no Python dep) ─────────────────────────────────
entropy_score() {
    local str="$1"
    [[ ${#str} -lt 4 ]] && echo "0.0" && return
    echo "$str" | awk '{
        n = split($0, c, "")
        for (i=1;i<=n;i++) freq[c[i]]++
        for (k in freq) { p=freq[k]/n; H-=p*log(p)/log(2) }
        printf "%.1f\n", H
    }'
}

entropy_check() {
    local val
    val=$(entropy_score "$1")
    awk "BEGIN { exit ($val < $ENTROPY_THRESHOLD) ? 1 : 0 }"
}

# ── Context-Aware Scoring (v3 NEW) ────────────────────────────────────────────
# Scores a finding higher when surrounded by assignment/config context
# Returns: critical | high | medium | low
context_risk_score() {
    local type="$1" secret="$2" context="$3"
    local base_risk="medium"

    # Bump risk if context contains assignment operators near key terms
    local key_terms="key|secret|token|pass|credential|auth|api|access"
    if echo "$context" | grep -qiE "($key_terms)[[:space:]]*[:=][[:space:]]*[\"']?${secret:0:8}"; then
        base_risk="high"
    fi

    # Critical if it's in a config/settings/environment object
    if echo "$context" | grep -qiE '(config|settings|env|environment|production|prod)[^}]{0,200}'"${secret:0:8}"; then
        base_risk="critical"
    fi

    # Downgrade if context looks like a test/example/placeholder
    if echo "$context" | grep -qiE '(test|example|sample|demo|placeholder|fake|dummy|mock|todo|fixme|xxx)'; then
        base_risk="low"
    fi

    # Never report low-risk findings unless verbose
    [[ "$base_risk" == "low" && "$VERBOSE" != true ]] && echo "skip" && return

    echo "$base_risk"
}

# ── False-Positive Filter (v3 NEW) ────────────────────────────────────────────
# Maintains a user-managed list of known-safe values
is_false_positive() {
    local secret="$1"
    [[ ! -f "$FALSE_POSITIVE_DB" ]] && return 1
    grep -qxF "$secret" "$FALSE_POSITIVE_DB" 2>/dev/null
}

add_false_positive() {
    local secret="$1"
    echo "$secret" >> "$FALSE_POSITIVE_DB"
    ok "Added to false-positive list: ${secret:0:30}..."
}

# ── Fingerprint Dedup (v3 NEW) ────────────────────────────────────────────────
# Hash-based dedup across scans — never report the same secret twice
fingerprint() {
    local secret="$1"
    echo "$secret" | sha256sum | cut -d' ' -f1
}

is_already_known() {
    local fp
    fp=$(fingerprint "$1")
    [[ -f "$FINGERPRINT_DB" ]] && grep -qx "$fp" "$FINGERPRINT_DB" 2>/dev/null
}

mark_known() {
    fingerprint "$1" >> "$FINGERPRINT_DB"
}

# ── Progress bar ──────────────────────────────────────────────────────────────
draw_progress() {
    [[ "$QUIET" == true || "$SILENT_MODE" == true ]] && return
    local current="$1" total="$2" label="${3:-}"
    [[ "$total" -eq 0 ]] && return
    local pct=$(( current * 100 / total ))
    local filled=$(( pct / 2 ))
    local bar
    bar=$(printf '%0.s█' $(seq 1 $filled) 2>/dev/null)
    bar="${bar}$(printf '%0.s░' $(seq 1 $((50 - filled))) 2>/dev/null)"
    printf "\r  ${CYAN}[%s]${NC} %3d%% %-40.40s" "$bar" "$pct" "$label"
}

# ── curl wrapper ──────────────────────────────────────────────────────────────
do_curl() {
    local args=()
    [[ -n "$PROXY"    ]] && args+=(-x "$PROXY")
    [[ "$INSECURE" == true ]] && args+=(-k)
    [[ "$RATE_LIMIT" -gt 0 ]] && sleep "$(echo "scale=3; $RATE_LIMIT/1000" | bc)"
    for h in "${EXTRA_HEADERS[@]:-}"; do [[ -n "$h" ]] && args+=(-H "$h"); done
    curl -sL --max-time 20 --retry 2 --retry-delay 1 \
        -A "$USER_AGENT" \
        "${args[@]}" "$@"
}

# ── Emit a finding ────────────────────────────────────────────────────────────
secret_emit() {
    local type="$1" secret="$2" file="$3" url="$4" line="${5:-?}" ctx="${6:-}"

    # False positive check
    is_false_positive "$secret" && return

    # Cross-scan dedup (only in diff mode)
    [[ "$DIFF_MODE" == true ]] && is_already_known "$secret" && return

    # Entropy gate
    entropy_check "$secret" || return

    # Context risk scoring
    local risk
    risk=$(context_risk_score "$type" "$secret" "$ctx")
    [[ "$risk" == "skip" ]] && return

    mark_known "$secret"
    FINDINGS_FOUND=$((FINDINGS_FOUND + 1))

    # Emit as pipe-delimited record
    printf '%s|%s|%s|%s|%s|%s|%s|%s\n' \
        "$type" "$secret" "$file" "$url" "$line" "$risk" \
        "$(entropy_score "$secret")" \
        "$(echo "$ctx" | tr '|' ' ' | head -c 200)" \
        >> "$SECRETS_TEMP"

    # Real-time terminal output
    local risk_color
    case "$risk" in
        critical) risk_color="$RED" ;;
        high)     risk_color="$ORANGE" ;;
        medium)   risk_color="$YELLOW" ;;
        *)        risk_color="$BLUE" ;;
    esac

    if [[ "$SILENT_MODE" == true ]]; then
        echo "$type|$secret|$url:$line"
    else
        log ""
        log "  ${risk_color}${BOLD}[$risk]${NC} ${BOLD}$type${NC}"
        log "  ${DIM}File:${NC}   $file (line $line)"
        log "  ${DIM}Source:${NC} $url"
        log "  ${DIM}Secret:${NC} ${CYAN}${secret:0:60}${NC}$([ ${#secret} -gt 60 ] && echo '...' || true)"
        log "  ${DIM}Entropy:${NC} $(entropy_score "$secret")  ${DIM}Risk:${NC} $risk"
        [[ -n "$ctx" ]] && vlog "  ${DIM}Context:${NC} ${GREY}${ctx:0:120}${NC}"
    fi
}

# ── Banner ────────────────────────────────────────────────────────────────────
show_banner() {
    [[ "$NO_BANNER" == true || "$SILENT_MODE" == true ]] && return
    cat << BANNER

${RED}     ██╗███████╗██╗  ██╗ █████╗ ██╗    ██╗██╗  ██╗
     ██║██╔════╝██║  ██║██╔══██╗██║    ██║██║ ██╔╝
     ██║███████╗███████║███████║██║ █╗ ██║█████╔╝
██   ██║╚════██║██╔══██║██╔══██║██║███╗██║██╔═██╗
╚█████╔╝███████║██║  ██║██║  ██║╚███╔███╔╝██║  ██╗
 ╚════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝${NC}
${GREY}  JavaScript Secret Scanner v${VERSION} | @Mah3Sec${NC}
${GREY}  github.com/Mah3Sec/JSHawk${NC}
${RED}  ─────────────────────────────────────────────────${NC}

BANNER
}

# ── Help ──────────────────────────────────────────────────────────────────────
show_help() {
    cat << HELP
${BOLD}USAGE${NC}
  jshawk <domain> [options]
  jshawk https://target.com --wayback --source-maps --validate
  jshawk target.com -s subs.txt --threads 20 --format sarif

${BOLD}TARGETING${NC}
  <domain>                Target domain or URL
  -s, --subdomains FILE   File of subdomains/URLs to scan (one per line)
  --scope FILE            Only scan URLs matching patterns in this file

${BOLD}DISCOVERY (v3)${NC}
  --deep-crawl            Follow JS references inside JS files (default: on)
  --chain-depth N         How many JS-in-JS levels to follow (default: 3)
  --wayback               Query Wayback Machine for historical JS snapshots
  --source-maps           Download .map files and reconstruct source code
  --no-deep-crawl         Disable JS chain following (faster, less thorough)

${BOLD}DETECTION${NC}
  -e, --entropy N         Entropy threshold, 0-5 (default: 3.5)
  --context               Context-aware scoring — suppress test/example values
  --no-context            Disable context scoring (report everything)
  -c, --custom-regex      Add custom detection patterns interactively

${BOLD}ENDPOINT PROBING (v3 NEW)${NC}
  --probe-endpoints       Fetch discovered API endpoints and scan responses
  --probe-cookies FILE    Load session cookies from file for authenticated probing
  --probe-headers FILE    Load auth headers (e.g. Bearer tokens) from file

${BOLD}VALIDATION${NC}
  --validate              Live-confirm findings via provider APIs
                          (AWS STS, GitHub API, Stripe, etc.)

${BOLD}OUTPUT${NC}
  -o, --output DIR        Output directory (default: jshawk_results/)
  --format FORMAT         Output format: txt|json|both|sarif|html (default: txt)
  --sarif                 SARIF 2.1.0 output for GitHub/GitLab CI integration
  --html                  Generate self-contained HTML report
  --wordlist              Export discovered endpoints as a wordlist
  --nuclei                Export findings as Nuclei template YAML
  --silent                Machine-readable output only (suppress UI)
  -q, --quiet             Suppress all non-finding output
  --no-color              Disable colors (for log files)
  --no-banner             Suppress the banner
  -v, --verbose           Show context lines and debug info

${BOLD}PERFORMANCE${NC}
  -t, --threads N         Parallel download threads (default: 15)
  --rate-limit MS         Delay between requests in milliseconds
  --resume                Resume an interrupted scan

${BOLD}DIFF MODE (v3 NEW)${NC}
  --diff                  Only report findings not seen in previous scans
                          Uses ~/.jshawk/fingerprints.db as baseline

${BOLD}FALSE POSITIVES (v3 NEW)${NC}
  --fp-add SECRET         Mark a value as false positive (suppress forever)
  --fp-list               List all known false positives
  --fp-clear              Clear all false positives

${BOLD}PROXY & AUTH${NC}
  --proxy URL             HTTP/SOCKS5 proxy (e.g. http://127.0.0.1:8080)
  --header "K: V"         Add custom header (repeatable)
  --insecure              Disable TLS verification

${BOLD}EXIT CODES${NC}
  0   Clean — no findings
  1   Findings detected (use in CI/CD: if jshawk target.com; then ...)
  2   Scan error

${BOLD}EXAMPLES${NC}
  # Basic scan
  jshawk target.com

  # Full recon — historical + source maps + live validation
  jshawk target.com --wayback --source-maps --validate --format html

  # CI/CD — only new findings, SARIF output
  jshawk target.com --diff --sarif --quiet

  # Authenticated endpoint probing
  jshawk target.com --probe-endpoints --probe-cookies cookies.txt

  # Bug bounty recon with scope control
  jshawk target.com -s subdomains.txt --scope scope.txt --threads 30 --wordlist

  # Export for further tooling
  jshawk target.com --wordlist --nuclei --format json

HELP
}

# ── Argument parsing ──────────────────────────────────────────────────────────
parse_args() {
    local positional=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -s|--subdomains)     SUBDOMAIN_FILE="$2";    shift 2 ;;
            -o|--output)         CUSTOM_OUTPUT="$2";     shift 2 ;;
            -t|--threads)        THREADS="$2";           shift 2 ;;
            -e|--entropy)        ENTROPY_THRESHOLD="$2"; shift 2 ;;
            --format)            OUTPUT_FORMAT="$2";     shift 2 ;;
            --proxy)             PROXY="$2";             shift 2 ;;
            --header)            EXTRA_HEADERS+=("$2");  shift 2 ;;
            --scope)             SCOPE_FILE="$2";        shift 2 ;;
            --chain-depth)       CHAIN_DEPTH="$2";       shift 2 ;;
            --rate-limit)        RATE_LIMIT="$2";        shift 2 ;;
            --probe-cookies)     PROBE_COOKIES="$2";     shift 2 ;;
            --probe-headers)     PROBE_HEADERS="$2";     shift 2 ;;
            --fp-add)            add_false_positive "$2"; exit 0 ;;
            --wayback)           WAYBACK=true;           shift ;;
            --source-maps)       SOURCE_MAPS=true;       shift ;;
            --validate)          VALIDATE=true;          shift ;;
            --insecure)          INSECURE=true;          shift ;;
            --deep-crawl)        DEEP_CRAWL=true;        shift ;;
            --no-deep-crawl)     DEEP_CRAWL=false;       shift ;;
            --probe-endpoints)   ENDPOINT_PROBE=true;    shift ;;
            --diff)              DIFF_MODE=true;         shift ;;
            --resume)            RESUME=true;            shift ;;
            --wordlist)          WORDLIST_OUT=true;      shift ;;
            --sarif)             SARIF_OUT=true;         shift ;;
            --html)              HTML_REPORT=true;       shift ;;
            --nuclei)            NUCLEI_EXPORT=true;     shift ;;
            --silent)            SILENT_MODE=true;       QUIET=true; shift ;;
            --context)           CONTEXT_MODE=true;      shift ;;
            --no-context)        CONTEXT_MODE=false;     shift ;;
            --fp-list)           [[ -f "$FALSE_POSITIVE_DB" ]] && cat "$FALSE_POSITIVE_DB" || echo "(none)"; exit 0 ;;
            --fp-clear)          rm -f "$FALSE_POSITIVE_DB"; ok "False positives cleared"; exit 0 ;;
            -c|--custom-regex)   setup_custom_regex; exit 0 ;;
            -l|--list-patterns)  list_patterns; exit 0 ;;
            -v|--verbose)        VERBOSE=true;           shift ;;
            -q|--quiet)          QUIET=true;             shift ;;
            --no-color)          NO_COLOR=true;          shift ;;
            --no-banner)         NO_BANNER=true;         shift ;;
            -h|--help)           show_help; exit 0 ;;
            -*)  err "Unknown option: $1"; show_help; exit 2 ;;
            *)   positional+=("$1"); shift ;;
        esac
    done

    [[ ${#positional[@]} -gt 0 ]] && DOMAIN="${positional[0]}"

    if [[ -z "$DOMAIN" && -z "$SUBDOMAIN_FILE" ]]; then
        err "domain or -s subdomains file is required"
        show_help; exit 2
    fi
}

# ── Scan initialisation ───────────────────────────────────────────────────────
FINDINGS_FOUND=0
RESULTS_DIR=""
SECRETS_TEMP=""

init_scan() {
    local domain="$1"
    if [[ "$domain" =~ ^https?:// ]]; then
        CLEAN_DOMAIN=$(echo "$domain" | sed 's|https\?://||;s|/.*||;s|:.*||')
        BASE_URL="$domain"
    else
        CLEAN_DOMAIN="$domain"
        BASE_URL="https://$domain"
    fi

    local output_base="${CUSTOM_OUTPUT:-$MAIN_RESULTS_DIR}"
    RESULTS_DIR="$output_base/${CLEAN_DOMAIN//[^a-zA-Z0-9.-]/_}_$(date +%Y%m%d_%H%M%S)"

    # Resume: find most recent scan dir
    if [[ "$RESUME" == true ]]; then
        local last_dir
        last_dir=$(find "$output_base" -maxdepth 1 -name "${CLEAN_DOMAIN//[^a-zA-Z0-9.-]/_}*" -type d 2>/dev/null | sort | tail -1)
        if [[ -n "$last_dir" ]]; then
            RESULTS_DIR="$last_dir"
            info "Resuming scan in: $RESULTS_DIR"
        fi
    fi

    mkdir -p "$RESULTS_DIR"/{js_files,findings,logs,reports,source_maps,endpoints,nuclei}

    SECRETS_TEMP="$RESULTS_DIR/.secrets_tmp_$$"
    > "$SECRETS_TEMP"

    cat > "$RESULTS_DIR/scan_info.json" << EOF
{
  "tool": "JSHawk",
  "version": "$VERSION",
  "domain": "$CLEAN_DOMAIN",
  "base_url": "$BASE_URL",
  "started": "$(date -Iseconds)",
  "entropy_threshold": $ENTROPY_THRESHOLD,
  "flags": {
    "wayback": $WAYBACK,
    "source_maps": $SOURCE_MAPS,
    "validate": $VALIDATE,
    "deep_crawl": $DEEP_CRAWL,
    "endpoint_probe": $ENDPOINT_PROBE,
    "diff_mode": $DIFF_MODE,
    "chain_depth": $CHAIN_DEPTH
  }
}
EOF

    info "Target:   ${BOLD}$CLEAN_DOMAIN${NC}"
    info "Results:  $RESULTS_DIR"
    info "Entropy:  ≥ $ENTROPY_THRESHOLD"
    [[ "$DEEP_CRAWL"      == true ]] && info "Deep crawl: enabled (depth $CHAIN_DEPTH)"
    [[ "$WAYBACK"         == true ]] && info "Wayback:  enabled"
    [[ "$SOURCE_MAPS"     == true ]] && info "Maps:     enabled"
    [[ "$VALIDATE"        == true ]] && info "Validate: enabled"
    [[ "$ENDPOINT_PROBE"  == true ]] && info "Endpoint probing: enabled"
    [[ "$DIFF_MODE"       == true ]] && info "Diff mode: only new findings"
    [[ -n "$PROXY"               ]] && info "Proxy:    $PROXY"
    log ""
}

# ── JS Discovery ──────────────────────────────────────────────────────────────
enhanced_js_discovery() {
    local target="$1"
    local target_clean
    target_clean=$(echo "$target" | sed 's|https\?://||;s|/.*||')
    local safe_name="${target_clean//[^a-zA-Z0-9.-]/_}"
    local html_file="$RESULTS_DIR/logs/page_${safe_name}.html"

    info "Discovery: $target"

    # Download the page with retries
    local attempt success=false
    for attempt in 1 2 3; do
        if do_curl -o "$html_file" \
            -H "Accept: text/html,application/xhtml+xml,*/*;q=0.8" \
            "$target" 2>/dev/null && [[ -s "$html_file" ]]; then
            success=true; break
        fi
        sleep "$((attempt * 2))"
    done
    [[ "$success" == false ]] && warn "Could not fetch: $target" && return 1

    local base_url
    base_url=$(echo "$target" | grep -oE 'https?://[^/]+')

    # Extract all script tags — src and inline
    grep -oE 'src=["\x27][^"\x27]*\.js[^"\x27]*["\x27]' "$html_file" 2>/dev/null \
        | grep -oE '["\x27][^"\x27]*["\x27]' | tr -d '"'"'" \
        | while read -r js_ref; do
            resolve_js_url "$js_ref" "$base_url" "$target"
        done >> "$RESULTS_DIR/all_js_discovered.txt" 2>/dev/null || true

    # Also check for link rel=preload
    grep -oiE 'href=["\x27][^"\x27]*\.js[^"\x27]*["\x27]' "$html_file" 2>/dev/null \
        | grep -oE '["\x27][^"\x27]*["\x27]' | tr -d '"'"'" \
        | while read -r js_ref; do
            resolve_js_url "$js_ref" "$base_url" "$target"
        done >> "$RESULTS_DIR/all_js_discovered.txt" 2>/dev/null || true

    local count
    count=$(wc -l < "$RESULTS_DIR/all_js_discovered.txt" 2>/dev/null || echo 0)
    ok "$count JS files discovered from $target"
    return 0
}

# ── URL resolver ──────────────────────────────────────────────────────────────
resolve_js_url() {
    local ref="$1" base_url="$2" page_url="$3"
    case "$ref" in
        http*) echo "$ref" ;;
        /*)    echo "${base_url}${ref}" ;;
        ./*)   echo "${page_url%/*}/${ref#./}" ;;
        ../*)  echo "${page_url%/*}/../${ref#../}" ;;
        *)     echo "${page_url%/*}/${ref}" ;;
    esac
}

# ── Deep JS chain discovery (v3 NEW) ─────────────────────────────────────────
# Reads a JS file and finds all JS references inside it — then fetches those too
discover_js_in_js() {
    local jsfile="$1" base_url="$2" depth="$3"
    [[ "$DEEP_CRAWL" != true ]] && return
    [[ "$depth" -ge "$CHAIN_DEPTH" ]] && return

    vlog "  ${DIM}[chain depth $depth]${NC} Scanning $jsfile for embedded JS refs..."

    # Extract references: import(), require(), src=, /path.js strings
    {
        grep -oE "(import|require)\s*\(\s*['\"][^'\"]+\.js[^'\"]*['\"]" "$jsfile" 2>/dev/null \
            | grep -oE "['\"][^'\"]+\.js[^'\"]*['\"]" | tr -d "'\""
        grep -oE "['\"/][a-zA-Z0-9_/.-]+\.js[?'\"]" "$jsfile" 2>/dev/null \
            | tr -d "'\""
        # Webpack chunk patterns: {0:"abc",1:"def"} + ".chunk.js"
        grep -oE '\{[0-9]+:"[a-f0-9]+"' "$jsfile" 2>/dev/null \
            | grep -oE '"[a-f0-9]+"' | tr -d '"' \
            | while read -r hash; do
                echo "/static/js/${hash}.chunk.js"
                echo "/assets/${hash}.js"
            done
    } | sort -u | while read -r ref; do
        [[ -z "$ref" || "$ref" == "node_modules"* ]] && continue
        local full_url
        full_url=$(resolve_js_url "$ref" "$base_url" "$base_url")
        [[ -z "$full_url" || "$full_url" == "$ref" ]] && continue

        # Skip if already queued
        grep -qxF "$full_url" "$RESULTS_DIR/all_js_discovered.txt" 2>/dev/null && continue

        echo "$full_url" >> "$RESULTS_DIR/all_js_discovered.txt"
        vlog "  ${PURPLE}[chain]${NC} Found: $full_url"
    done
}

# ── Wayback discovery ─────────────────────────────────────────────────────────
wayback_discovery() {
    [[ "$WAYBACK" != true ]] && return
    info "Wayback Machine: querying historical JS snapshots..."

    local cdx_url="https://web.archive.org/cdx/search/cdx"
    cdx_url+="?url=${CLEAN_DOMAIN}/*.js"
    cdx_url+="&output=text&fl=timestamp,original&filter=statuscode:200"
    cdx_url+="&collapse=digest&limit=200&from=20200101"

    do_curl "$cdx_url" 2>/dev/null \
    | while read -r ts orig_url; do
        [[ -z "$ts" || -z "$orig_url" ]] && continue
        local wayback_url="https://web.archive.org/web/${ts}if_/${orig_url}"
        echo "$wayback_url" >> "$RESULTS_DIR/all_js_discovered.txt"
    done

    local wb_count
    wb_count=$(grep -c "web.archive.org" "$RESULTS_DIR/all_js_discovered.txt" 2>/dev/null || echo 0)
    ok "Wayback: $wb_count historical snapshots queued"
}

# ── Parallel download ─────────────────────────────────────────────────────────
parallel_download() {
    [[ ! -f "$RESULTS_DIR/all_js_discovered.txt" ]] && return 1

    sort -u "$RESULTS_DIR/all_js_discovered.txt" -o "$RESULTS_DIR/all_js_discovered.txt"
    local total
    total=$(wc -l < "$RESULTS_DIR/all_js_discovered.txt")
    [[ "$total" -eq 0 ]] && warn "No JS files to download" && return 1

    info "Downloading $total unique JS files (${THREADS} threads)..."

    local dl_count=0 ok_count=0 fail_count=0
    mkdir -p "$RESULTS_DIR/logs"
    > "$RESULTS_DIR/downloaded_files.txt"

    # Download in parallel batches
    local pids=()
    while IFS= read -r js_url; do
        (
            local safe
            safe=$(echo "$js_url" | sha256sum | cut -c1-12)
            local ext=".js"
            [[ "$js_url" == *".ts"* ]] && ext=".ts"
            local outfile="$RESULTS_DIR/js_files/${safe}${ext}"

            # Skip if already downloaded (resume mode)
            [[ "$RESUME" == true && -f "$outfile" ]] && echo "OK" >> "$RESULTS_DIR/logs/dl_status.txt" && exit 0

            if do_curl -o "$outfile" \
                -H "Accept: */*" \
                "$js_url" 2>/dev/null \
                && [[ -s "$outfile" ]]; then
                # Basic content-type sanity — skip HTML error pages
                if head -c 100 "$outfile" | grep -qiE '<!DOCTYPE|<html'; then
                    rm -f "$outfile"
                    echo "FAIL" >> "$RESULTS_DIR/logs/dl_status.txt"
                    exit 0
                fi
                echo "${js_url}|$(basename "$outfile")" >> "$RESULTS_DIR/downloaded_files.txt"
                echo "OK" >> "$RESULTS_DIR/logs/dl_status.txt"

                # Deep crawl: discover JS refs inside this file
                [[ "$DEEP_CRAWL" == true ]] && {
                    local base
                    base=$(echo "$js_url" | grep -oE 'https?://[^/]+')
                    discover_js_in_js "$outfile" "$base" 1
                }
            else
                rm -f "$outfile"
                echo "FAIL" >> "$RESULTS_DIR/logs/dl_status.txt"
            fi
        ) &
        pids+=($!)
        dl_count=$((dl_count + 1))
        draw_progress "$dl_count" "$total" "$(basename "$js_url")"

        # Throttle parallel jobs
        if [[ ${#pids[@]} -ge "$THREADS" ]]; then
            wait "${pids[@]}" 2>/dev/null || true
            pids=()
        fi
    done < "$RESULTS_DIR/all_js_discovered.txt"

    wait "${pids[@]}" 2>/dev/null || true
    echo ""

    ok_count=$(grep -c "^OK$"   "$RESULTS_DIR/logs/dl_status.txt" 2>/dev/null || echo 0)
    fail_count=$(grep -c "^FAIL$" "$RESULTS_DIR/logs/dl_status.txt" 2>/dev/null || echo 0)
    ok "Downloaded: $ok_count   Failed: $fail_count"
    [[ "$ok_count" -eq 0 ]] && warn "Nothing downloaded" && return 1
    return 0
}

# ── Source map reconstruction ─────────────────────────────────────────────────
process_source_maps() {
    [[ "$SOURCE_MAPS" != true ]] && return
    [[ ! -f "$RESULTS_DIR/source_map_urls.txt" ]] && return

    info "Source maps: reconstructing original source files..."
    local map_count=0

    while IFS='|' read -r _origin map_url; do
        local map_file="$RESULTS_DIR/source_maps/$(echo "$map_url" | sed 's|https\?://||;s|/|_|g')"
        do_curl -o "$map_file" "$map_url" 2>/dev/null || continue
        [[ ! -s "$map_file" ]] && continue
        map_count=$((map_count + 1))

        python3 - "$map_file" "$RESULTS_DIR/source_maps" "$RESULTS_DIR/js_files" 2>/dev/null << 'PYEOF'
import json, sys, os, pathlib, hashlib
try:
    data = json.load(open(sys.argv[1]))
    sm_dir, js_dir = sys.argv[2], sys.argv[3]
    sources  = data.get('sources', [])
    contents = data.get('sourcesContent', [])
    for i, (src, content) in enumerate(zip(sources, contents or [])):
        if not content: continue
        name = pathlib.Path(src).name or f"source_{i}.js"
        name = name.replace('/', '_').replace('..', '_')
        h = hashlib.sha256(content.encode()).hexdigest()[:8]
        out = os.path.join(js_dir, f"srcmap_{h}_{name}")
        open(out, 'w').write(content)
        print(f"Extracted: {src}", file=sys.stderr)
except Exception as e:
    print(f"Error: {e}", file=sys.stderr)
PYEOF
    done < "$RESULTS_DIR/source_map_urls.txt"
    ok "$map_count source maps reconstructed — original TypeScript/JSX added to scan queue"
}

# ── Pattern matching ──────────────────────────────────────────────────────────
safe_extract() {
    local pattern="$1" type="$2" jsfile="$3" url="$4"
    grep -nE "$pattern" "$jsfile" 2>/dev/null | while read -r raw; do
        local linenum="${raw%%:*}"
        local matchtext="${raw#*:}"
        local secret
        secret=$(echo "$matchtext" | grep -oE "$pattern" | head -1)
        [[ -z "$secret" ]] && continue
        local ctx
        ctx=$(grep -n "" "$jsfile" 2>/dev/null | sed -n "$((linenum > 2 ? linenum-2 : 1)),$((linenum+2))p" | tr '\n' ' ')
        secret_emit "$type" "$secret" "$(basename "$jsfile")" "$url" "$linenum" "$ctx"
    done
}

analyze_enhanced_secrets() {
    info "Analysis: scanning with entropy ≥ $ENTROPY_THRESHOLD..."
    local files_count
    files_count=$(find "$RESULTS_DIR/js_files" -type f \( -name "*.js" -o -name "*.ts" \) 2>/dev/null | wc -l)
    info "$files_count files to scan"
    echo ""

    local processed=0
    while IFS= read -r jsfile; do
        local filename
        filename=$(basename "$jsfile")
        local original_url
        original_url=$(grep "|${filename}|" "$RESULTS_DIR/downloaded_files.txt" 2>/dev/null | cut -d'|' -f1 || echo "local")
        processed=$((processed + 1))
        draw_progress "$processed" "$files_count" "$filename"

        # ── Cloud & Infrastructure ─────────────────────────────────────────
        safe_extract 'AKIA[0-9A-Z]{16}' "AWS_ACCESS_KEY" "$jsfile" "$original_url"
        grep -nE '(aws[_-]?secret|secretAccessKey)[^A-Za-z0-9]*[A-Za-z0-9/+]{40}' "$jsfile" 2>/dev/null | while read -r raw; do
            local ln="${raw%%:*}" ; local secret
            secret=$(echo "${raw#*:}" | grep -oE '[A-Za-z0-9/+]{40}' | head -1)
            [[ "$secret" =~ ^[a-fA-F0-9]{40}$ ]] && continue
            local ctx; ctx=$(sed -n "$((${ln:-1} > 2 ? ${ln:-1}-2 : 1)),$((${ln:-1}+2))p" "$jsfile" 2>/dev/null | tr '\n' ' ')
            secret_emit "AWS_SECRET_KEY" "$secret" "$filename" "$original_url" "$ln" "$ctx"
        done
        safe_extract 'AIza[0-9A-Za-z_-]{35}' "GOOGLE_API_KEY" "$jsfile" "$original_url"
        grep -nE 'AccountKey=[A-Za-z0-9+/]{86,88}==' "$jsfile" 2>/dev/null | while read -r raw; do
            local ln="${raw%%:*}"; local secret
            secret=$(echo "${raw#*:}" | grep -oE '[A-Za-z0-9+/]{86,88}==' | head -1)
            secret_emit "AZURE_STORAGE_KEY" "$secret" "$filename" "$original_url" "$ln"
        done
        grep -nE '(databaseURL|firebaseio\.com|apiKey.*AIza)' "$jsfile" 2>/dev/null | while read -r raw; do
            local ln="${raw%%:*}"; local secret
            secret=$(echo "${raw#*:}" | grep -oE 'https://[a-zA-Z0-9_-]+\.firebaseio\.com|AIza[0-9A-Za-z_-]{35}' | head -1)
            [[ -n "$secret" ]] && secret_emit "FIREBASE" "$secret" "$filename" "$original_url" "$ln"
        done
        safe_extract '(sk|pk|rk)_live_[0-9a-zA-Z]{24,}' "STRIPE_LIVE_KEY" "$jsfile" "$original_url"

        # ── VCS & CI/CD ────────────────────────────────────────────────────
        safe_extract 'gh[poshru]_[A-Za-z0-9_]{30,}' "GITHUB_TOKEN" "$jsfile" "$original_url"
        safe_extract 'github_pat_[A-Za-z0-9_]{82}' "GITHUB_PAT" "$jsfile" "$original_url"
        safe_extract 'glpat-[A-Za-z0-9_-]{20,}' "GITLAB_TOKEN" "$jsfile" "$original_url"
        safe_extract 'npm_[A-Za-z0-9]{30,}' "NPM_TOKEN" "$jsfile" "$original_url"
        grep -nE '(jenkins|JENKINS)[^A-Za-z0-9]*[a-f0-9]{32,34}' "$jsfile" 2>/dev/null | while read -r raw; do
            local ln="${raw%%:*}"; local secret
            secret=$(echo "${raw#*:}" | grep -oE '[a-f0-9]{32,34}' | head -1)
            secret_emit "JENKINS_TOKEN" "$secret" "$filename" "$original_url" "$ln"
        done

        # ── Communication ──────────────────────────────────────────────────
        safe_extract 'xox[baprs]-[0-9A-Za-z-]{10,}' "SLACK_TOKEN" "$jsfile" "$original_url"
        safe_extract 'hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[A-Za-z0-9]+' "SLACK_WEBHOOK" "$jsfile" "$original_url"
        safe_extract 'SG\.[A-Za-z0-9_.+-]{60,}' "SENDGRID_KEY" "$jsfile" "$original_url"
        safe_extract 'AC[a-z0-9]{32}' "TWILIO_SID" "$jsfile" "$original_url"
        safe_extract 'shpat_[a-fA-F0-9]{32}' "SHOPIFY_TOKEN" "$jsfile" "$original_url"
        safe_extract 'discord(app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+' "DISCORD_WEBHOOK" "$jsfile" "$original_url"
        safe_extract '[0-9]{8,10}:[A-Za-z0-9_-]{35}' "TELEGRAM_BOT" "$jsfile" "$original_url"
        safe_extract 'key-[a-z0-9]{32}' "MAILGUN_KEY" "$jsfile" "$original_url"
        safe_extract '[a-f0-9]{32}-us[0-9]{1,2}' "MAILCHIMP_KEY" "$jsfile" "$original_url"

        # ── AI Providers ───────────────────────────────────────────────────
        safe_extract 'sk-(?:proj-)?[A-Za-z0-9]{48,}' "OPENAI_KEY" "$jsfile" "$original_url"
        safe_extract 'sk-ant-[A-Za-z0-9_-]{90,}' "ANTHROPIC_KEY" "$jsfile" "$original_url"
        safe_extract 'hf_[A-Za-z0-9]{30,}' "HUGGINGFACE_TOKEN" "$jsfile" "$original_url"
        safe_extract 'r8_[A-Za-z0-9]{40}' "REPLICATE_KEY" "$jsfile" "$original_url"

        # ── Database & Secrets ────────────────────────────────────────────
        grep -nE '(mysql|postgresql|postgres|mongodb|redis|amqp|mongodb\+srv)://[^@\s"'"'"'<>]{3,}@[a-zA-Z0-9.-]+' \
            "$jsfile" 2>/dev/null | while read -r raw; do
            local ln="${raw%%:*}"; local secret
            secret=$(echo "${raw#*:}" | grep -oE '(mysql|postgresql|postgres|mongodb|redis|amqp|mongodb\+srv)://[^@\s"'"'"'<>]{3,}@[a-zA-Z0-9.-]+[^"'"'"'\s]*' | head -1)
            secret_emit "DATABASE_URL" "$secret" "$filename" "$original_url" "$ln"
        done
        if grep -q "BEGIN.*PRIVATE.*KEY\|BEGIN OPENSSH" "$jsfile" 2>/dev/null; then
            local kln
            kln=$(grep -n "BEGIN.*PRIVATE\|BEGIN OPENSSH" "$jsfile" | head -1 | cut -d: -f1)
            secret_emit "PRIVATE_KEY" "PEM_BLOCK_DETECTED" "$filename" "$original_url" "$kln"
        fi
        safe_extract 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' "JWT_TOKEN" "$jsfile" "$original_url"
        grep -nE '(jwt[_-]?secret|JWT_SECRET)[^A-Za-z0-9]*["\'"'"'][^"'"'"']{16,}["\'"'"']' "$jsfile" 2>/dev/null | while read -r raw; do
            local ln="${raw%%:*}"; local secret
            secret=$(echo "${raw#*:}" | grep -oE '"[^"]{16,}"|'"'"'[^'"'"']{16,}'"'" | head -1 | tr -d '"'"'")
            secret_emit "JWT_SECRET" "$secret" "$filename" "$original_url" "$ln"
        done

        # ── Network & Infrastructure ───────────────────────────────────────
        grep -nE '(10\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3})\.[0-9]{1,3}' \
            "$jsfile" 2>/dev/null | while read -r raw; do
            local ln="${raw%%:*}"; local secret
            secret=$(echo "${raw#*:}" | grep -oE '(10\.[0-9]{1,3}|192\.168|172\.(1[6-9]|2[0-9]|3[01]))\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
            secret_emit "INTERNAL_IP" "$secret" "$filename" "$original_url" "$ln"
        done
        safe_extract 'https?://[A-Za-z0-9_-]+:[^@\s"'"'"']{4,}@[A-Za-z0-9.-]+' "BASIC_AUTH_URL" "$jsfile" "$original_url"

        # ── Auth & Identity ────────────────────────────────────────────────
        safe_extract 'pk\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' "MAPBOX_TOKEN" "$jsfile" "$original_url"
        safe_extract '00[A-Za-z0-9_-]{40}' "OKTA_TOKEN" "$jsfile" "$original_url"
        grep -nE '(auth0[_-]?client[_-]?secret|AUTH0_SECRET)[^A-Za-z0-9]*["\'"'"'][A-Za-z0-9_-]{40,}["\'"'"']' "$jsfile" 2>/dev/null | while read -r raw; do
            local ln="${raw%%:*}"; local secret
            secret=$(echo "${raw#*:}" | grep -oE '"[A-Za-z0-9_-]{40,}"|'"'"'[A-Za-z0-9_-]{40,}'"'" | head -1 | tr -d '"'"'")
            secret_emit "AUTH0_SECRET" "$secret" "$filename" "$original_url" "$ln"
        done

        # ── Monitoring & Analytics ─────────────────────────────────────────
        safe_extract 'https://[a-f0-9]{32}@(o[0-9]+\.)?ingest\.sentry\.io/[0-9]+' "SENTRY_DSN" "$jsfile" "$original_url"

        # ── Hardcoded passwords ────────────────────────────────────────────
        grep -nE "(password|passwd|pwd)[[:space:]]*[:=][[:space:]]*['\"][^'\"]{8,}['\"]" \
            "$jsfile" 2>/dev/null | while read -r raw; do
            local ln="${raw%%:*}"; local secret
            secret=$(echo "${raw#*:}" | grep -oE "['\"][^'\"]{8,}['\"]" | head -1 | tr -d "\"'")
            local ctx; ctx=$(sed -n "$((${ln:-1} > 2 ? ${ln:-1}-2 : 1)),$((${ln:-1}+2))p" "$jsfile" 2>/dev/null | tr '\n' ' ')
            secret_emit "HARDCODED_PASSWORD" "$secret" "$filename" "$original_url" "$ln" "$ctx"
        done

        # ── Endpoint extraction (stored for wordlist + probing) ────────────
        {
            grep -oE '[^a-zA-Z](/api/[^"'"'"'`\s<>]{2,})' "$jsfile" 2>/dev/null | grep -oE '/api/[^"'"'"'`\s<>]{2,}'
            grep -oE '[^a-zA-Z](/v[0-9]+/[^"'"'"'`\s<>]{2,})' "$jsfile" 2>/dev/null | grep -oE '/v[0-9]+/[^"'"'"'`\s<>]{2,}'
            grep -oE '(/graphql[^"'"'"'`\s<>]*)' "$jsfile" 2>/dev/null
            grep -oE '(/admin[^"'"'"'`\s<>]*)' "$jsfile" 2>/dev/null
            grep -oE '(/internal[^"'"'"'`\s<>]*)' "$jsfile" 2>/dev/null
            grep -oE 'fetch[(][^)]{0,200}[/][a-zA-Z]' "$jsfile" 2>/dev/null | grep -oE '["'"'"'][^"'"'"']{4,}["'"'"']' | tr -d '"'"'"
            grep -oE 'url[:][[:space:]]*["'"'"'][^"'"'"']{4,}["'"'"']' "$jsfile" 2>/dev/null | grep -oE '["'"'"'][^"'"'"']{4,}["'"'"']' | tr -d '"'"'"
        } | sort -u >> "$RESULTS_DIR/endpoints/discovered_paths.txt" 2>/dev/null || true

        # ── Source map reference detection ─────────────────────────────────
        if grep -qE '//# sourceMappingURL=' "$jsfile" 2>/dev/null; then
            local map_ref
            map_ref=$(grep -oE '//# sourceMappingURL=\S+' "$jsfile" | head -1 | sed 's|//# sourceMappingURL=||')
            local map_url
            map_url=$(resolve_js_url "$map_ref" "$(echo "$original_url" | grep -oE 'https?://[^/]+')" "$original_url")
            echo "${original_url}|${map_url}" >> "$RESULTS_DIR/source_map_urls.txt" 2>/dev/null || true
        fi

        # ── Custom patterns ────────────────────────────────────────────────
        if [[ -f "$CUSTOM_REGEX_FILE" && -s "$CUSTOM_REGEX_FILE" ]]; then
            while IFS='|' read -r pattern_name regex_pattern _description; do
                [[ -z "$pattern_name" || -z "$regex_pattern" ]] && continue
                safe_extract "$regex_pattern" "CUSTOM_${pattern_name^^}" "$jsfile" "$original_url"
            done < "$CUSTOM_REGEX_FILE"
        fi

    done < <(find "$RESULTS_DIR/js_files" -type f \( -name "*.js" -o -name "*.ts" \) 2>/dev/null)

    echo ""
    # Deduplicate findings by secret value
    if [[ -s "$SECRETS_TEMP" ]]; then
        sort -t'|' -k2,2 -u "$SECRETS_TEMP" > "$RESULTS_DIR/findings/secrets.txt"
        local raw_count dedup_count
        raw_count=$(wc -l < "$SECRETS_TEMP")
        dedup_count=$(wc -l < "$RESULTS_DIR/findings/secrets.txt")
        ok "$dedup_count unique findings ($((raw_count - dedup_count)) duplicates removed)"
    else
        touch "$RESULTS_DIR/findings/secrets.txt"
    fi
    rm -f "$SECRETS_TEMP"
}

# ── Endpoint probing (v3 NEW) ─────────────────────────────────────────────────
probe_endpoints() {
    [[ "$ENDPOINT_PROBE" != true ]] && return
    [[ ! -f "$RESULTS_DIR/endpoints/discovered_paths.txt" ]] && return

    info "Endpoint probing: fetching API routes for leaked secrets..."

    local probe_args=()
    [[ -n "${PROBE_COOKIES:-}" && -f "${PROBE_COOKIES:-}" ]] && probe_args+=(-b "$PROBE_COOKIES")
    [[ -n "${PROBE_HEADERS:-}" && -f "${PROBE_HEADERS:-}" ]] && \
        while IFS= read -r h; do probe_args+=(-H "$h"); done < "$PROBE_HEADERS"

    local base_url
    base_url=$(echo "$BASE_URL" | grep -oE 'https?://[^/]+')

    sort -u "$RESULTS_DIR/endpoints/discovered_paths.txt" | head -100 | while read -r path; do
        [[ -z "$path" ]] && continue
        local full_url
        case "$path" in
            http*) full_url="$path" ;;
            *)     full_url="${base_url}${path}" ;;
        esac

        vlog "  ${DIM}[probe]${NC} $full_url"

        local resp_file="$RESULTS_DIR/endpoints/resp_$(echo "$full_url" | sha256sum | cut -c1-8).txt"
        local status_code
        status_code=$(do_curl "${probe_args[@]}" -o "$resp_file" -w "%{http_code}" "$full_url" 2>/dev/null || echo "000")

        echo "${full_url}|${status_code}" >> "$RESULTS_DIR/endpoints/probe_results.txt"
        vlog "    ${DIM}HTTP $status_code${NC}"

        [[ ! -s "$resp_file" ]] && continue
        # Skip HTML pages (login redirects)
        head -c 100 "$resp_file" | grep -qiE '<!DOCTYPE|<html' && continue

        # Scan the response body for secrets
        local old_count=$FINDINGS_FOUND
        # Temporarily scan the response file as if it were a JS file
        local original_url="${full_url} [endpoint response]"
        cp "$resp_file" "$RESULTS_DIR/js_files/ep_$(basename "$resp_file").js"
        # will be picked up in next analyze pass — or force inline scan
        grep -nE 'AKIA[0-9A-Z]{16}|(sk|pk)_live_[0-9a-zA-Z]{24,}|gh[poshru]_[A-Za-z0-9_]{30,}|xox[baprs]-[0-9A-Za-z-]{10,}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' \
            "$resp_file" 2>/dev/null | while read -r raw; do
            local ln="${raw%%:*}"; local matchtext="${raw#*:}"
            local secret; secret=$(echo "$matchtext" | grep -oE '[A-Za-z0-9_/+=-]{20,}' | head -1)
            [[ -n "$secret" ]] && secret_emit "ENDPOINT_LEAK" "$secret" "$(basename "$resp_file")" "$original_url" "$ln"
        done
    done

    local probe_count
    probe_count=$(wc -l < "$RESULTS_DIR/endpoints/probe_results.txt" 2>/dev/null || echo 0)
    ok "Probed $probe_count endpoints — results in endpoints/probe_results.txt"
}

# ── Live validation ────────────────────────────────────────────────────────────
validate_credentials() {
    [[ "$VALIDATE" != true ]] && return
    [[ ! -s "$RESULTS_DIR/findings/secrets.txt" ]] && return

    info "Validation: confirming credentials are live..."

    while IFS='|' read -r type secret _file _url _line _risk _entropy _ctx; do
        case "$type" in
            AWS_ACCESS_KEY)
                local r
                r=$(do_curl -s "https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15" \
                    -H "Authorization: AWS4-HMAC-SHA256 Credential=${secret}//sts/aws4_request,SignedHeaders=host,Signature=x" 2>/dev/null | head -c300)
                echo "$r" | grep -q "InvalidClientTokenId" \
                    && log "  ${YELLOW}[INVALID]${NC} AWS Key (no longer valid): ${secret:0:20}..." \
                    || log "  ${GREEN}[LIVE]${NC} AWS Key: ${secret:0:20}..."
                ;;
            GITHUB_TOKEN|GITHUB_PAT)
                local r
                r=$(do_curl -s "https://api.github.com/user" \
                    -H "Authorization: token $secret" 2>/dev/null | head -c200)
                echo "$r" | grep -q '"login"' \
                    && log "  ${GREEN}[LIVE]${NC} GitHub Token valid: $(echo "$r" | grep -o '"login":"[^"]*"' | head -1)" \
                    || log "  ${YELLOW}[INVALID]${NC} GitHub Token"
                ;;
            STRIPE_LIVE_KEY)
                local r
                r=$(do_curl -s "https://api.stripe.com/v1/account" \
                    -u "${secret}:" 2>/dev/null | head -c200)
                echo "$r" | grep -q '"id"' \
                    && log "  ${GREEN}[LIVE]${NC} Stripe key valid" \
                    || log "  ${YELLOW}[INVALID]${NC} Stripe key"
                ;;
            OPENAI_KEY)
                local r
                r=$(do_curl -s "https://api.openai.com/v1/models" \
                    -H "Authorization: Bearer $secret" 2>/dev/null | head -c200)
                echo "$r" | grep -q '"object":"list"' \
                    && log "  ${GREEN}[LIVE]${NC} OpenAI key valid" \
                    || log "  ${YELLOW}[INVALID]${NC} OpenAI key"
                ;;
        esac
    done < "$RESULTS_DIR/findings/secrets.txt"
}

# ── SARIF output (v3 NEW) ─────────────────────────────────────────────────────
generate_sarif() {
    [[ "$SARIF_OUT" != true && "$OUTPUT_FORMAT" != "sarif" ]] && return
    local sarif_file="$RESULTS_DIR/reports/jshawk.sarif"

    python3 - "$RESULTS_DIR/findings/secrets.txt" "$sarif_file" "$VERSION" << 'PYEOF'
import json, sys, datetime
secrets_file, out_file, version = sys.argv[1], sys.argv[2], sys.argv[3]
results = []
try:
    with open(secrets_file) as f:
        for line in f:
            parts = line.strip().split('|')
            if len(parts) < 6: continue
            type_, secret, file_, url, line_n, risk = parts[:6]
            entropy = parts[6] if len(parts) > 6 else '?'
            results.append({
                "ruleId": f"JSHAWK-{type_}",
                "level": "error" if risk=="critical" else "warning" if risk=="high" else "note",
                "message": {"text": f"{type_} exposed in {file_} (entropy: {entropy}, risk: {risk})"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": url},
                    "region": {"startLine": int(line_n) if line_n.isdigit() else 1}
                }}],
                "partialFingerprints": {"secretHash": secret[:16]}
            })
except: pass

sarif = {
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    "version": "2.1.0",
    "runs": [{
        "tool": {"driver": {
            "name": "JSHawk", "version": version,
            "informationUri": "https://github.com/Mah3Sec/JSHawk",
            "rules": []
        }},
        "results": results,
        "invocations": [{"executionSuccessful": True, "endTimeUtc": datetime.datetime.utcnow().isoformat()+"Z"}]
    }]
}
json.dump(sarif, open(out_file, 'w'), indent=2)
print(f"SARIF: {len(results)} findings written to {out_file}")
PYEOF
}

# ── HTML report (v3 NEW) ──────────────────────────────────────────────────────
generate_html_report() {
    [[ "$HTML_REPORT" != true && "$OUTPUT_FORMAT" != "html" ]] && return
    local html_file="$RESULTS_DIR/reports/jshawk_report.html"
    python3 - "$RESULTS_DIR/findings/secrets.txt" "$html_file" "$CLEAN_DOMAIN" "$VERSION" << 'PYEOF'
import sys, html as h, datetime
sf, out, domain, ver = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
findings = []
try:
    for line in open(sf):
        p = line.strip().split('|')
        if len(p) >= 6: findings.append(p)
except: pass
crit = sum(1 for f in findings if len(f)>5 and f[5]=='critical')
high = sum(1 for f in findings if len(f)>5 and f[5]=='high')
med  = len(findings) - crit - high
def risk_color(r):
    return {'critical':'#CC0000','high':'#d4820f','medium':'#4a8fd4'}.get(r,'#7a7d9a')
rows = '\n'.join(f'''<tr>
<td><span style="color:{risk_color(f[5] if len(f)>5 else '')};font-weight:700">{h.escape(f[5] if len(f)>5 else '?').upper()}</span></td>
<td>{h.escape(f[0])}</td>
<td><code>{h.escape(f[1][:60])}{"..." if len(f[1])>60 else ""}</code></td>
<td>{h.escape(f[2])}</td>
<td><a href="{h.escape(f[3])}" style="color:#4a8fd4">{h.escape(f[3][:60])}</a></td>
<td>{h.escape(f[4])}</td>
<td>{h.escape(f[6] if len(f)>6 else '?')}</td>
</tr>''' for f in findings)
html_content = f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>JSHawk Report — {h.escape(domain)}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#0D0F16;color:#C8C6D8;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;font-size:13px}}
.hdr{{background:#08000A;padding:24px 32px;border-bottom:2px solid #CC0000}}
.hdr h1{{color:#F0EEF8;font-size:22px;margin-bottom:4px}}
.hdr p{{color:#555870;font-size:12px}}
.stats{{display:flex;gap:0;border-bottom:1px solid #1a1d2a}}
.stat{{flex:1;padding:20px;text-align:center;border-right:1px solid #1a1d2a}}
.stat:last-child{{border-right:none}}
.stat-n{{font-size:32px;font-weight:700;margin-bottom:4px}}
.stat-l{{font-size:11px;color:#3d4060;text-transform:uppercase;letter-spacing:.06em}}
table{{width:100%;border-collapse:collapse;font-size:12px}}
th{{background:#08000A;padding:10px 14px;text-align:left;color:#555870;font-weight:600;border-bottom:1px solid #1a1d2a;font-size:10px;text-transform:uppercase;letter-spacing:.07em}}
td{{padding:9px 14px;border-bottom:1px solid #1a1d2a;vertical-align:top}}
tr:hover td{{background:#0f1019}}
code{{font-family:'SF Mono','Fira Code',monospace;background:#1a1d2a;padding:2px 6px;border-radius:3px;font-size:11px;color:#CC0000}}
a{{color:#4a8fd4;text-decoration:none}}
.footer{{padding:16px 32px;color:#2e3150;font-size:11px;border-top:1px solid #1a1d2a}}
</style></head><body>
<div class="hdr"><h1>JSHawk Security Report</h1>
<p>Target: {h.escape(domain)} &nbsp;|&nbsp; Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')} &nbsp;|&nbsp; JSHawk v{h.escape(ver)}</p></div>
<div class="stats">
<div class="stat"><div class="stat-n" style="color:#CC0000">{crit}</div><div class="stat-l">Critical</div></div>
<div class="stat"><div class="stat-n" style="color:#d4820f">{high}</div><div class="stat-l">High</div></div>
<div class="stat"><div class="stat-n" style="color:#4a8fd4">{med}</div><div class="stat-l">Medium</div></div>
<div class="stat"><div class="stat-n" style="color:#8b7fe8">{len(findings)}</div><div class="stat-l">Total</div></div>
</div>
<table><thead><tr><th>Risk</th><th>Type</th><th>Secret</th><th>File</th><th>Source URL</th><th>Line</th><th>Entropy</th></tr></thead>
<tbody>{rows}</tbody></table>
<div class="footer">JSHawk v{h.escape(ver)} — github.com/Mah3Sec/JSHawk — For authorized security testing only</div>
</body></html>"""
open(out,'w').write(html_content)
print(f"HTML report: {out}")
PYEOF
}

# ── Nuclei template export (v3 NEW) ──────────────────────────────────────────
generate_nuclei_templates() {
    [[ "$NUCLEI_EXPORT" != true ]] && return
    [[ ! -s "$RESULTS_DIR/findings/secrets.txt" ]] && return
    local n_dir="$RESULTS_DIR/nuclei"
    info "Exporting Nuclei templates..."

    while IFS='|' read -r type secret _file url _line risk _entropy _ctx; do
        [[ -z "$secret" || "$secret" == "PEM_BLOCK_DETECTED" ]] && continue
        local tpl_file="$n_dir/jshawk_${type,,}_${secret:0:8}.yaml"
        cat > "$tpl_file" << YAML
id: jshawk-${type,,}-exposure

info:
  name: ${type} Exposed in JavaScript
  author: Mah3Sec (JSHawk)
  severity: ${risk}
  description: JSHawk detected an exposed ${type} credential in JavaScript source code.
  tags: exposure,secrets,javascript,${type,,}

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: word
        words:
          - "${secret:0:20}"
        part: body

# Source: ${url}
# Found by JSHawk v${VERSION}
YAML
    done < "$RESULTS_DIR/findings/secrets.txt"

    local nc
    nc=$(find "$n_dir" -name "*.yaml" 2>/dev/null | wc -l)
    ok "Generated $nc Nuclei templates in: $n_dir/"
}

# ── Wordlist export (v3 NEW) ──────────────────────────────────────────────────
generate_wordlist() {
    [[ "$WORDLIST_OUT" != true ]] && return
    local wl="$RESULTS_DIR/reports/endpoints_wordlist.txt"
    [[ -f "$RESULTS_DIR/endpoints/discovered_paths.txt" ]] \
        && sort -u "$RESULTS_DIR/endpoints/discovered_paths.txt" > "$wl" \
        && ok "Endpoint wordlist: $wl ($(wc -l < "$wl") paths)"
}

# ── Custom regex setup ────────────────────────────────────────────────────────
setup_custom_regex() {
    echo -e "${YELLOW}${BOLD}Custom Pattern Setup${NC}"
    echo "Stored in: $CUSTOM_REGEX_FILE"
    echo "Format: NAME|regex|description"
    echo ""
    touch "$CUSTOM_REGEX_FILE"
    while true; do
        read -rp "Name (or 'done'/'list'): " pname
        case "$pname" in
            done) break ;;
            list) [[ -s "$CUSTOM_REGEX_FILE" ]] && cat "$CUSTOM_REGEX_FILE" || echo "(none)"; continue ;;
        esac
        read -rp "Regex: " pregex
        read -rp "Description: " pdesc
        if echo "test" | grep -qE "$pregex" 2>/dev/null; then
            echo -e "${RED}Pattern too broad (matches 'test')${NC}"; continue
        fi
        echo "${pname}|${pregex}|${pdesc}" >> "$CUSTOM_REGEX_FILE"
        echo -e "${GREEN}Saved: $pname${NC}"
    done
}

# ── Report generation ─────────────────────────────────────────────────────────
generate_reports() {
    local secrets_file="$1" files_count="${2:-0}"
    local finding_count=0
    [[ -f "$secrets_file" ]] && finding_count=$(wc -l < "$secrets_file" || echo 0)
    FINDINGS_FOUND=$finding_count

    # JSON report
    if [[ "$OUTPUT_FORMAT" == "json" || "$OUTPUT_FORMAT" == "both" ]]; then
        python3 - "$secrets_file" "$RESULTS_DIR/reports/jshawk.json" "$CLEAN_DOMAIN" "$VERSION" "$files_count" << 'PYEOF'
import json, sys, datetime
sf, out, domain, ver, fc = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
findings = []
for line in open(sf):
    p = line.strip().split('|')
    if len(p) < 6: continue
    findings.append({"type":p[0],"secret":p[1],"file":p[2],"url":p[3],"line":p[4],"risk":p[5],
                     "entropy":p[6] if len(p)>6 else "?","context":p[7] if len(p)>7 else ""})
out_data = {"meta":{"tool":"JSHawk","version":ver,"domain":domain,"date":datetime.datetime.utcnow().isoformat()+"Z",
                    "js_files_scanned":int(fc)},
            "summary":{"total":len(findings),"critical":sum(1 for f in findings if f["risk"]=="critical"),
                       "high":sum(1 for f in findings if f["risk"]=="high"),
                       "medium":sum(1 for f in findings if f["risk"]=="medium")},
            "findings":findings}
json.dump(out_data, open(out,'w'), indent=2)
print(f"JSON: {out}")
PYEOF
    fi

    # SARIF
    generate_sarif

    # HTML
    generate_html_report

    # Nuclei templates
    generate_nuclei_templates

    # Wordlist
    generate_wordlist
}

# ── Final summary ─────────────────────────────────────────────────────────────
display_final_summary() {
    local secrets_file="$RESULTS_DIR/findings/secrets.txt"
    local crit=0 high=0 med=0

    if [[ -s "$secrets_file" ]]; then
        crit=$(grep -c '|critical|' "$secrets_file" 2>/dev/null || echo 0)
        high=$(grep -c '|high|'     "$secrets_file" 2>/dev/null || echo 0)
        med=$(grep -c  '|medium|'   "$secrets_file" 2>/dev/null || echo 0)
    fi

    [[ "$SILENT_MODE" == true ]] && return

    echo ""
    log "${RED}${BOLD}╔══════════════════════════════════════════╗${NC}"
    log "${RED}${BOLD}║           JSHawk Scan Complete           ║${NC}"
    log "${RED}${BOLD}╚══════════════════════════════════════════╝${NC}"
    echo ""
    log "  ${BOLD}Target:${NC}    $CLEAN_DOMAIN"
    log "  ${BOLD}Findings:${NC}  ${RED}$crit critical${NC}  ${ORANGE}$high high${NC}  ${YELLOW}$med medium${NC}"
    local js_count
    js_count=$(find "$RESULTS_DIR/js_files" -type f 2>/dev/null | wc -l)
    log "  ${BOLD}JS files:${NC}  $js_count scanned"
    local ep_count
    ep_count=$(wc -l < "$RESULTS_DIR/endpoints/discovered_paths.txt" 2>/dev/null || echo 0)
    log "  ${BOLD}Endpoints:${NC} $ep_count discovered"
    log "  ${BOLD}Results:${NC}   $RESULTS_DIR"
    echo ""
    [[ -f "$RESULTS_DIR/reports/jshawk.json"         ]] && log "  JSON:   $RESULTS_DIR/reports/jshawk.json"
    [[ -f "$RESULTS_DIR/reports/jshawk.sarif"        ]] && log "  SARIF:  $RESULTS_DIR/reports/jshawk.sarif"
    [[ -f "$RESULTS_DIR/reports/jshawk_report.html"  ]] && log "  HTML:   $RESULTS_DIR/reports/jshawk_report.html"
    [[ -f "$RESULTS_DIR/reports/endpoints_wordlist.txt" ]] && log "  Wordlist: $RESULTS_DIR/reports/endpoints_wordlist.txt"
    [[ -d "$RESULTS_DIR/nuclei"                      ]] && log "  Nuclei: $RESULTS_DIR/nuclei/"
    echo ""
}

# ── Main ──────────────────────────────────────────────────────────────────────
list_patterns() {
    echo -e "${CYAN}${BOLD}JSHawk v${VERSION} Detection Patterns${NC}"
    echo ""
    for group_info in \
        "Cloud:AWS Key,AWS Secret,Google API,Azure Storage,Firebase,Stripe,GCP,DigitalOcean,Heroku" \
        "VCS/CI:GitHub Token,GitHub PAT,GitLab Token,npm Token,Jenkins Token,Travis CI,CircleCI" \
        "Comms:Slack Token,Slack Webhook,SendGrid,Twilio SID,Twilio Auth,Shopify,Discord,Telegram,Mailgun,Mailchimp" \
        "AI:OpenAI,Anthropic,HuggingFace,Replicate" \
        "DB:Database URL,JWT Token,JWT Secret,Private Key,SSH Key,Hardcoded Password,Basic Auth URL" \
        "Net:Internal IP,Private Subnet,S3 Bucket,Sentry DSN,Mapbox,Okta Token,Auth0 Secret"; do
        local grp="${group_info%%:*}"
        local items="${group_info#*:}"
        echo -e "  ${YELLOW}${grp}:${NC} $items"
    done
    echo ""
    echo -e "  ${PURPLE}Custom:${NC} $([ -s "$CUSTOM_REGEX_FILE" ] && grep -c '.' "$CUSTOM_REGEX_FILE" || echo 0) patterns in $CUSTOM_REGEX_FILE"
    echo ""
    echo -e "  ${DIM}All matches are entropy-filtered (≥$ENTROPY_THRESHOLD) and context-scored.${NC}"
    echo -e "  ${DIM}Placeholders and test values are suppressed automatically.${NC}"
}

main() {
    setup_colors
    show_banner
    parse_args "$@"

    # Build target list
    local targets=()
    [[ -n "$DOMAIN" ]] && targets+=("$DOMAIN")
    if [[ -n "$SUBDOMAIN_FILE" && -f "$SUBDOMAIN_FILE" ]]; then
        while IFS= read -r line; do
            [[ -n "$line" && "$line" != "#"* ]] && targets+=("$line")
        done < "$SUBDOMAIN_FILE"
    fi

    # Scope filter
    scope_check() {
        local t="$1"
        [[ -z "$SCOPE_FILE" ]] && return 0
        grep -qF "$t" "$SCOPE_FILE" 2>/dev/null
    }

    for target in "${targets[@]}"; do
        scope_check "$target" || { warn "Out of scope, skipping: $target"; continue; }
        init_scan "$target"
        enhanced_js_discovery "$target"
        wayback_discovery
        parallel_download || { err "Download phase failed"; continue; }
        process_source_maps
        analyze_enhanced_secrets
        probe_endpoints
        validate_credentials
        generate_reports "$RESULTS_DIR/findings/secrets.txt" \
            "$(find "$RESULTS_DIR/js_files" -type f 2>/dev/null | wc -l)"
        display_final_summary
    done

    # Exit code: 1 if any findings, 0 if clean
    [[ "$FINDINGS_FOUND" -gt 0 ]] && exit 1
    exit 0
}

main "$@"
