#!/usr/bin/env bash
# JSHawk v3.1 - Advanced JavaScript Secret Scanner
# Author: Mahendra Purbia (@Mah3Sec)
# GitHub: https://github.com/Mah3Sec/JSHawk
# For authorized security testing only

set -uo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
ORANGE='\033[38;5;208m'
GREY='\033[38;5;240m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# Config
readonly VERSION="3.1"
readonly CONFIG_DIR="$HOME/.jshawk"
readonly CUSTOM_REGEX_FILE="$CONFIG_DIR/custom_patterns.txt"
readonly FINGERPRINT_DB="$CONFIG_DIR/fingerprints.db"
readonly FALSE_POSITIVE_DB="$CONFIG_DIR/false_positives.txt"
readonly MAIN_RESULTS_DIR="jshawk_results"

mkdir -p "$CONFIG_DIR"

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
PROBE_COOKIES=""
PROBE_HEADERS=""
DEEP_CRAWL=true
ENDPOINT_PROBE=false
CONTEXT_MODE=true
DIFF_MODE=false
RESUME=false
WORDLIST_OUT=false
CHAIN_DEPTH=3
RATE_LIMIT=0
SILENT_MODE=false
HTML_REPORT=false
SARIF_OUT=false
NUCLEI_EXPORT=false
FINDINGS_FOUND=0
RESULTS_DIR=""
SECRETS_TEMP=""
CLEAN_DOMAIN=""
BASE_URL=""

UA_LIST=(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 Version/17.4 Safari/605.1.15"
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0"
)
USER_AGENT="${UA_LIST[$((RANDOM % ${#UA_LIST[@]}))]}"

# Helpers
log()  { if [[ "$QUIET" != true && "$SILENT_MODE" != true ]]; then echo -e "$@"; fi; }
vlog() { if [[ "$VERBOSE" == true && "$QUIET" != true ]]; then echo -e "$@"; fi; }
info() { log "${BLUE}[*]${NC} $*"; }
ok()   { log "${GREEN}[+]${NC} $*"; }
warn() { log "${YELLOW}[!]${NC} $*" >&2; }
err()  { echo -e "${RED}[ERROR]${NC} $*" >&2; }
found_log() { log "${RED}[FOUND]${NC} $*"; }

setup_colors() {
    if [[ "$NO_COLOR" == true ]]; then
        RED='' GREEN='' YELLOW='' BLUE='' PURPLE=''
        CYAN='' ORANGE='' GREY='' BOLD='' DIM='' NC=''
    fi
}

# Shannon entropy (pure awk)
entropy_score() {
    local str="$1"
    if [[ ${#str} -lt 4 ]]; then
        echo "0.0"
        return
    fi
    echo "$str" | awk '{
        n=split($0,c,"")
        for(i=1;i<=n;i++) freq[c[i]]++
        H=0
        for(k in freq){p=freq[k]/n; H-=p*log(p)/log(2)}
        printf "%.1f\n",H
    }'
}

entropy_passes() {
    local str="$1"
    local score
    score=$(entropy_score "$str")
    awk "BEGIN{exit ($score >= $ENTROPY_THRESHOLD)?0:1}" 2>/dev/null
    return $?
}

# False positive management
is_false_positive() {
    [[ ! -f "$FALSE_POSITIVE_DB" ]] && return 1
    grep -qxF "$1" "$FALSE_POSITIVE_DB" 2>/dev/null
    return $?
}

add_false_positive() {
    echo "$1" >> "$FALSE_POSITIVE_DB"
    ok "Added to false-positive list: ${1:0:40}"
}

# Fingerprint dedup across scans
fingerprint() {
    echo "$1" | sha256sum | cut -d' ' -f1
}

is_already_known() {
    [[ "$DIFF_MODE" != true ]] && return 1
    [[ ! -f "$FINGERPRINT_DB" ]] && return 1
    local fp
    fp=$(fingerprint "$1")
    grep -qx "$fp" "$FINGERPRINT_DB" 2>/dev/null
    return $?
}

mark_known() {
    fingerprint "$1" >> "$FINGERPRINT_DB"
}

# Context-aware risk scoring
context_risk_score() {
    local secret="$1" context="$2"
    local base_risk="medium"

    if echo "$context" | grep -qiE "(key|secret|token|pass|credential|auth|api|access)[[:space:]]*[:=]" 2>/dev/null; then
        base_risk="high"
    fi
    if echo "$context" | grep -qiE "(config|settings|env|environment|production|prod)" 2>/dev/null; then
        base_risk="critical"
    fi
    if echo "$context" | grep -qiE "(test|example|sample|demo|placeholder|fake|dummy|mock|todo|fixme)" 2>/dev/null; then
        if [[ "$VERBOSE" != true ]]; then
            echo "skip"
            return 0
        fi
        base_risk="low"
    fi
    echo "$base_risk"
}

# Progress bar
draw_progress() {
    [[ "$QUIET" == true || "$SILENT_MODE" == true ]] && return
    local current="$1" total="$2" label="${3:-}"
    [[ "$total" -eq 0 ]] && return
    local pct=$(( current * 100 / total ))
    local filled=$(( pct / 2 ))
    local bar="" i
    for ((i=0; i<filled; i++)); do bar="${bar}#"; done
    for ((i=filled; i<50; i++)); do bar="${bar}-"; done
    printf "\r  [%s] %3d%% %-40.40s" "$bar" "$pct" "$label"
}

# curl wrapper
do_curl() {
    local args=(-sL --max-time 20 --retry 2 --retry-delay 1 -A "$USER_AGENT")
    [[ -n "$PROXY"    ]] && args+=(-x "$PROXY")
    [[ "$INSECURE" == true ]] && args+=(-k)
    if [[ "$RATE_LIMIT" -gt 0 ]]; then
        local secs
        secs=$(awk "BEGIN{printf \"%.3f\",$RATE_LIMIT/1000}")
        sleep "$secs" 2>/dev/null || true
    fi
    local h
    for h in "${EXTRA_HEADERS[@]:-}"; do
        [[ -n "$h" ]] && args+=(-H "$h")
    done
    curl "${args[@]}" "$@"
}

# Emit a secret finding
secret_emit() {
    local type="$1" secret="$2" file="$3" url="$4" line="${5:-?}" ctx="${6:-}"

    [[ -z "$secret" || ${#secret} -lt 6 ]] && return
    [[ ${#secret} -gt 500 ]] && return

    if is_false_positive "$secret"; then return; fi
    if is_already_known "$secret"; then return; fi
    if ! entropy_passes "$secret"; then return; fi

    local risk="medium"
    if [[ "$CONTEXT_MODE" == true ]]; then
        risk=$(context_risk_score "$secret" "$ctx")
        [[ "$risk" == "skip" ]] && return
    fi

    mark_known "$secret"
    FINDINGS_FOUND=$(( FINDINGS_FOUND + 1 ))

    local ent
    ent=$(entropy_score "$secret")

    local safe_ctx
    safe_ctx=$(echo "$ctx" | tr '|' ' ' | head -c 200)

    printf '%s|%s|%s|%s|%s|%s|%s|%s\n' \
        "$type" "$secret" "$file" "$url" "$line" "$risk" "$ent" "$safe_ctx" \
        >> "$SECRETS_TEMP"

    if [[ "$SILENT_MODE" == true ]]; then
        echo "${type}|${secret}|${url}:${line}"
        return
    fi

    local rc
    case "$risk" in
        critical) rc="$RED"    ;;
        high)     rc="$ORANGE" ;;
        medium)   rc="$YELLOW" ;;
        *)        rc="$BLUE"   ;;
    esac

    log ""
    log "  ${rc}${BOLD}[$risk]${NC} ${BOLD}${type}${NC}"
    log "  ${DIM}File:${NC}    $file  (line $line)"
    log "  ${DIM}Source:${NC}  $url"
    log "  ${DIM}Secret:${NC}  ${CYAN}${secret:0:72}${NC}"
    log "  ${DIM}Entropy:${NC} $ent  ${DIM}Risk:${NC} $risk"
    if [[ -n "$ctx" ]]; then
        vlog "  ${DIM}Context:${NC} ${GREY}${ctx:0:120}${NC}"
    fi
}

# Banner
show_banner() {
    [[ "$NO_BANNER" == true || "$SILENT_MODE" == true ]] && return
    echo -e "${RED}"
    echo '     ██╗███████╗██╗  ██╗ █████╗ ██╗    ██╗██╗  ██╗'
    echo '     ██║██╔════╝██║  ██║██╔══██╗██║    ██║██║ ██╔╝'
    echo '     ██║███████╗███████║███████║██║ █╗ ██║█████╔╝ '
    echo '██   ██║╚════██║██╔══██║██╔══██║██║███╗██║██╔═██╗ '
    echo '╚█████╔╝███████║██║  ██║██║  ██║╚███╔███╔╝██║  ██╗'
    echo ' ╚════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝'
    echo -e "${NC}${GREY}  JavaScript Secret Scanner v${VERSION} | @Mah3Sec${NC}"
    echo -e "${GREY}  github.com/Mah3Sec/JSHawk${NC}"
    echo -e "${RED}  =================================================${NC}"
    echo ""
}

# Help
show_help() {
    echo -e "${BOLD}USAGE${NC}"
    echo "  jshawk <domain> [options]"
    echo "  jshawk target.com --wayback --source-maps --validate --html"
    echo "  jshawk target.com -s subs.txt --threads 20 --diff --sarif"
    echo ""
    echo -e "${BOLD}TARGETING${NC}"
    echo "  <domain>                 Target domain or URL"
    echo "  -s, --subdomains FILE    File of subdomains/URLs to scan"
    echo "  --scope FILE             Only scan URLs matching patterns in this file"
    echo ""
    echo -e "${BOLD}DISCOVERY${NC}"
    echo "  --deep-crawl             Follow JS refs inside JS files [default: on]"
    echo "  --chain-depth N          JS-in-JS recursion depth [default: 3]"
    echo "  --wayback                Query Wayback Machine for historical JS"
    echo "  --source-maps            Download .map files, reconstruct source"
    echo "  --no-deep-crawl          Disable chain following (faster)"
    echo ""
    echo -e "${BOLD}DETECTION${NC}"
    echo "  -e, --entropy N          Entropy threshold 0-5 [default: 3.5]"
    echo "  --no-context             Disable context-aware scoring"
    echo "  -c, --custom-regex       Add custom patterns interactively"
    echo "  -l, --list-patterns      List all built-in patterns"
    echo ""
    echo -e "${BOLD}ENDPOINT PROBING${NC}"
    echo "  --probe-endpoints        Fetch API endpoints, scan responses"
    echo "  --probe-cookies FILE     Cookie file for authenticated probing"
    echo "  --probe-headers FILE     Header file (e.g. Authorization: Bearer ...)"
    echo ""
    echo -e "${BOLD}OUTPUT${NC}"
    echo "  -o, --output DIR         Output directory [default: jshawk_results/]"
    echo "  --format FORMAT          txt|json|both|sarif|html [default: txt]"
    echo "  --sarif                  SARIF 2.1.0 for GitHub/GitLab CI"
    echo "  --html                   Self-contained HTML report"
    echo "  --wordlist               Export endpoints as wordlist"
    echo "  --nuclei                 Export findings as Nuclei templates"
    echo "  --silent                 Machine-readable only"
    echo "  -q, --quiet              Suppress all non-finding output"
    echo "  --no-color               Disable colors"
    echo "  -v, --verbose            Show context lines and debug"
    echo ""
    echo -e "${BOLD}PERFORMANCE${NC}"
    echo "  -t, --threads N          Parallel threads [default: 15]"
    echo "  --rate-limit MS          Delay between requests (ms)"
    echo "  --resume                 Resume interrupted scan"
    echo ""
    echo -e "${BOLD}DIFF & FALSE POSITIVES${NC}"
    echo "  --diff                   Only report new findings vs last scan"
    echo "  --validate               Live-confirm via provider APIs"
    echo "  --fp-add SECRET          Mark as false positive (suppressed forever)"
    echo "  --fp-list                List false positives"
    echo "  --fp-clear               Clear all false positives"
    echo ""
    echo -e "${BOLD}PROXY & AUTH${NC}"
    echo "  --proxy URL              HTTP/SOCKS5 proxy"
    echo "  --header \"K: V\"          Custom header (repeatable)"
    echo "  --insecure               Disable TLS verification"
    echo ""
    echo -e "${BOLD}EXIT CODES${NC}"
    echo "  0  Clean -- no findings"
    echo "  1  Findings detected"
    echo "  2  Scan error"
    echo ""
    echo -e "${BOLD}EXAMPLES${NC}"
    echo "  jshawk target.com"
    echo "  jshawk target.com --wayback --source-maps --validate --html"
    echo "  jshawk target.com --diff --sarif --quiet"
    echo "  jshawk target.com --probe-endpoints --probe-cookies cookies.txt"
    echo "  jshawk target.com -s subs.txt --scope scope.txt --wordlist"
    echo "  jshawk target.com --nuclei --wordlist --format json"
}

# Argument parsing
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
            --fp-list)           [[ -f "$FALSE_POSITIVE_DB" ]] && cat "$FALSE_POSITIVE_DB" || echo "(none)"; exit 0 ;;
            --fp-clear)          rm -f "$FALSE_POSITIVE_DB"; ok "False positives cleared"; exit 0 ;;
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
            --silent)            SILENT_MODE=true; QUIET=true; shift ;;
            --context)           CONTEXT_MODE=true;      shift ;;
            --no-context)        CONTEXT_MODE=false;     shift ;;
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
        show_help
        exit 2
    fi
}

# Custom regex setup
setup_custom_regex() {
    echo -e "${YELLOW}${BOLD}Custom Pattern Setup${NC}"
    echo "Stored in: $CUSTOM_REGEX_FILE"
    touch "$CUSTOM_REGEX_FILE"
    while true; do
        read -rp "Name (or 'done'/'list'): " pname
        case "$pname" in
            done) break ;;
            list) [[ -s "$CUSTOM_REGEX_FILE" ]] && cat "$CUSTOM_REGEX_FILE" || echo "(none)"; continue ;;
        esac
        read -rp "Regex: " pregex
        read -rp "Description: " pdesc
        if echo "test_string_12345" | grep -qE "$pregex" 2>/dev/null; then
            echo -e "${RED}Pattern too broad (matches test string)${NC}"; continue
        fi
        echo "${pname}|${pregex}|${pdesc}" >> "$CUSTOM_REGEX_FILE"
        echo -e "${GREEN}Saved: $pname${NC}"
    done
}

list_patterns() {
    echo -e "${CYAN}${BOLD}JSHawk v${VERSION} Detection Patterns${NC}"
    echo ""
    echo -e "  ${RED}Critical:${NC}"
    echo -e "    AWS Access Key, AWS Secret Key, Azure Storage Key, Azure Connection String"
    echo -e "    Database URLs (MySQL/Postgres/MongoDB/Redis/AMQP), Stripe Live Keys"
    echo -e "    Private Key (PEM), SSH Private Key, Twilio Auth Token, Auth0 Client Secret"
    echo -e "    Heroku API Key, PayPal Client Secret, Braintree Key, Square Access Token"
    echo ""
    echo -e "  ${YELLOW}High:${NC}"
    echo -e "    GitHub Token + PAT, GitLab Token, npm Token, Jenkins Token"
    echo -e "    Travis CI Token, CircleCI Token"
    echo -e "    OpenAI Key, Anthropic Key, HuggingFace Token, Replicate Key"
    echo -e "    Slack Bot/User/App Token, Slack Webhook, SendGrid Key"
    echo -e "    Shopify Admin Token, Shopify API Secret, Discord Bot Token, Discord Webhook"
    echo -e "    Telegram Bot Token, Mailgun Key, Mailchimp Key"
    echo -e "    Firebase URL + API Key, Google API Key, GCP Service Account"
    echo -e "    DigitalOcean Token, Datadog API Key, New Relic License Key"
    echo ""
    echo -e "  ${BLUE}Medium:${NC}"
    echo -e "    JWT Token, JWT Secret, Hardcoded Password, Generic API Key, Generic Secret Key"
    echo -e "    Internal IP, Private Subnet CIDR, Basic Auth in URL, S3 Bucket URL"
    echo -e "    Sentry DSN, Mapbox Token, Okta Token, OAuth Client Secret"
    echo -e "    Amplitude API Key, Encryption Key"
    echo ""
    local cpcount=0
    [[ -f "$CUSTOM_REGEX_FILE" ]] && cpcount=$(wc -l < "$CUSTOM_REGEX_FILE" 2>/dev/null || echo 0)
    echo -e "  ${PURPLE}Custom:${NC} $cpcount patterns in $CUSTOM_REGEX_FILE"
    echo ""
    echo -e "  ${DIM}Total built-in patterns: 65+${NC}"
    echo -e "  ${DIM}All patterns filtered by Shannon entropy >= $ENTROPY_THRESHOLD${NC}"
    echo -e "  ${DIM}Context-aware scoring suppresses test/placeholder values${NC}"
}

# Scan initialisation
init_scan() {
    local domain="$1"
    local proto_stripped="${domain#http://}"
    proto_stripped="${proto_stripped#https://}"
    CLEAN_DOMAIN="${proto_stripped%%/*}"
    CLEAN_DOMAIN="${CLEAN_DOMAIN%%:*}"

    if [[ "$domain" =~ ^https?:// ]]; then
        BASE_URL="$domain"
    else
        BASE_URL="https://$domain"
    fi

    local output_base="${CUSTOM_OUTPUT:-$MAIN_RESULTS_DIR}"
    local ts
    ts=$(date +%Y%m%d_%H%M%S)
    local safe_name="${CLEAN_DOMAIN//[^a-zA-Z0-9.-]/_}"
    RESULTS_DIR="${output_base}/${safe_name}_${ts}"

    if [[ "$RESUME" == true ]]; then
        local last_dir
        last_dir=$(find "$output_base" -maxdepth 1 -name "${safe_name}_*" -type d 2>/dev/null | sort | tail -1)
        if [[ -n "$last_dir" ]]; then
            RESULTS_DIR="$last_dir"
            info "Resuming scan in: $RESULTS_DIR"
        fi
    fi

    mkdir -p "${RESULTS_DIR}/js_files" \
             "${RESULTS_DIR}/findings" \
             "${RESULTS_DIR}/logs" \
             "${RESULTS_DIR}/reports" \
             "${RESULTS_DIR}/source_maps" \
             "${RESULTS_DIR}/endpoints" \
             "${RESULTS_DIR}/nuclei"

    SECRETS_TEMP="${RESULTS_DIR}/.secrets_tmp_$$"
    > "$SECRETS_TEMP"

    # Write scan metadata as JSON
    python3 - "${RESULTS_DIR}/scan_info.json" "$CLEAN_DOMAIN" "$BASE_URL" "$VERSION" \
        "$ENTROPY_THRESHOLD" "$THREADS" "$DEEP_CRAWL" "$CHAIN_DEPTH" \
        "$WAYBACK" "$SOURCE_MAPS" "$VALIDATE" "$ENDPOINT_PROBE" "$DIFF_MODE" << 'PYEOF'
import json, sys, datetime
out = sys.argv[1]
data = {
    "tool": "JSHawk",
    "version": sys.argv[4],
    "domain": sys.argv[2],
    "base_url": sys.argv[3],
    "started": datetime.datetime.now().isoformat(),
    "config": {
        "entropy_threshold": float(sys.argv[5]),
        "threads": int(sys.argv[6]),
        "deep_crawl": sys.argv[7] == "true",
        "chain_depth": int(sys.argv[8]),
        "wayback": sys.argv[9] == "true",
        "source_maps": sys.argv[10] == "true",
        "validate": sys.argv[11] == "true",
        "endpoint_probe": sys.argv[12] == "true",
        "diff_mode": sys.argv[13] == "true"
    }
}
json.dump(data, open(out, 'w'), indent=2)
PYEOF

    info "Target:  ${BOLD}${CLEAN_DOMAIN}${NC}"
    info "Results: $RESULTS_DIR"
    info "Entropy: >= $ENTROPY_THRESHOLD"
    [[ "$DEEP_CRAWL"     == true ]] && info "Deep crawl: enabled (depth $CHAIN_DEPTH)"
    [[ "$WAYBACK"        == true ]] && info "Wayback:  enabled"
    [[ "$SOURCE_MAPS"    == true ]] && info "Maps:     enabled"
    [[ "$VALIDATE"       == true ]] && info "Validate: enabled"
    [[ "$ENDPOINT_PROBE" == true ]] && info "Endpoint probing: enabled"
    [[ "$DIFF_MODE"      == true ]] && info "Diff mode: only new findings"
    [[ -n "$PROXY"              ]] && info "Proxy:    $PROXY"
    log ""
}

# Resolve a JS URL relative to base
resolve_js_url() {
    local ref="$1" base_url="$2"
    base_url="${base_url%%/}"
    local origin
    origin=$(echo "$base_url" | grep -oE '^https?://[^/]+' || echo "https://${CLEAN_DOMAIN}")
    case "$ref" in
        https://*|http://*) echo "$ref" ;;
        //*) echo "https:${ref}" ;;
        /*)  echo "${origin}${ref}" ;;
        ./*)
            local dir="${base_url%/*}"
            echo "${dir}/${ref#./}"
            ;;
        ../*)
            local dir="${base_url%/*}"
            echo "${dir%/*}/${ref#../}"
            ;;
        "")  ;;
        *)
            local dir="${base_url%/*}"
            echo "${dir}/${ref}"
            ;;
    esac
}

# Extract JS src/href refs from an HTML file
extract_js_from_html() {
    local hf="$1"
    grep -oE 'src="[^"]+\.js[^"]*"'    "$hf" 2>/dev/null | sed 's/^src="//;s/"[^"]*$//'
    grep -oE "src='[^']+\\.js[^']*'"    "$hf" 2>/dev/null | sed "s/^src='//;s/'[^']*$//"
    grep -oE 'src=/[^[:space:]>"'"'"']+\.js[^[:space:]>"'"'"']*' "$hf" 2>/dev/null | sed 's/^src=//'
    grep -oiE 'href="[^"]+\.js[^"]*"'   "$hf" 2>/dev/null | sed 's/^[Hh][Rr][Ee][Ff]="//;s/"[^"]*$//'
    grep -oiE "href='[^']+\\.js[^']*'"  "$hf" 2>/dev/null | sed "s/^[Hh][Rr][Ee][Ff]='//;s/'[^']*$//"
    grep -oE '"[^"]*/_next/[^"]+\.js"'  "$hf" 2>/dev/null | tr -d '"'
    grep -oE '"[^"]*/assets/[^"]+\.js"' "$hf" 2>/dev/null | tr -d '"'
    grep -oE '"[^"]*/static/[^"]+\.js"' "$hf" 2>/dev/null | tr -d '"'
    grep -oE '"[^"]*/chunks/[^"]+\.js"' "$hf" 2>/dev/null | tr -d '"'
    grep -oE '"[^"]*/dist/[^"]+\.js"'   "$hf" 2>/dev/null | tr -d '"'
    grep -oE '"[^"]*/build/[^"]+\.js"'  "$hf" 2>/dev/null | tr -d '"'
}

# Parse webpack manifest JSON to extract all chunk URLs
parse_webpack_manifest() {
    local base_url="$1"
    # Common webpack manifest paths
    local manifest_paths=("/_next/static/chunks/webpack.js"
                          "/static/js/runtime-main.js"
                          "/asset-manifest.json"
                          "/webpack-manifest.json"
                          "/static/webpack-manifest.json"
                          "/manifest.json"
                          "/__webpack_hmr")
    local tmp
    tmp=$(mktemp)
    for p in "${manifest_paths[@]}"; do
        local murl="${base_url}${p}"
        local code
        code=$(do_curl -o "$tmp" -w "%{http_code}" "$murl" 2>/dev/null || echo "000")
        if [[ "$code" == "200" && -s "$tmp" ]]; then
            # Extract .js paths from JSON manifest
            grep -oE '"[^"]+\.js"' "$tmp" 2>/dev/null | tr -d '"' | while IFS= read -r jsref; do
                local resolved
                resolved=$(resolve_js_url "$jsref" "$base_url")
                [[ -n "$resolved" && "$resolved" =~ ^https?:// ]] && echo "$resolved"
            done >> "${RESULTS_DIR}/all_js_discovered.txt" || true
            vlog "  Webpack manifest parsed: $murl"
        fi
    done
    rm -f "$tmp"
}

enhanced_js_discovery() {
    local target="$1"
    local safe_name
    safe_name=$(echo "$target" | tr -cs 'a-zA-Z0-9.-' '_')
    local html_file="${RESULTS_DIR}/logs/page_${safe_name:0:60}.html"

    info "Discovery: $target"

    local fetch_url="$BASE_URL"
    [[ "$target" =~ ^https?:// ]] && fetch_url="$target"

    local effective_url="" attempt
    for attempt in 1 2 3; do
        effective_url=$(do_curl -o "$html_file" -w "%{url_effective}" "$fetch_url" 2>/dev/null || true)
        [[ -s "$html_file" ]] && break
        sleep $((attempt * 2))
    done

    if [[ ! -s "$html_file" ]]; then
        warn "Could not fetch: $fetch_url"
        return 1
    fi

    local base_url="https://${CLEAN_DOMAIN}"
    if [[ -n "$effective_url" && "$effective_url" =~ ^https?:// ]]; then
        base_url=$(echo "$effective_url" | grep -oE 'https?://[^/]+' || echo "https://${CLEAN_DOMAIN}")
    fi
    vlog "  Effective base: $base_url"

    touch "${RESULTS_DIR}/all_js_discovered.txt"

    extract_js_from_html "$html_file" | grep -v '^$' | sort -u | while IFS= read -r ref; do
        local resolved
        resolved=$(resolve_js_url "$ref" "$base_url")
        [[ -n "$resolved" && "$resolved" =~ ^https?:// ]] && echo "$resolved"
    done >> "${RESULTS_DIR}/all_js_discovered.txt"

    # Parse webpack/asset manifests
    parse_webpack_manifest "$base_url"

    local count
    count=$(wc -l < "${RESULTS_DIR}/all_js_discovered.txt" 2>/dev/null | tr -d '[:space:]')
    count="${count:-0}"

    # Retry with www. prefix if nothing found
    if [[ "$count" -eq 0 ]] && [[ ! "$fetch_url" =~ ://www\. ]]; then
        local www_url www_effective www_html
        www_url="https://www.${CLEAN_DOMAIN}"
        www_html="${RESULTS_DIR}/logs/page_www.html"
        vlog "  Retrying with www prefix: $www_url"
        www_effective=$(do_curl -o "$www_html" -w "%{url_effective}" "$www_url" 2>/dev/null || true)
        if [[ -s "$www_html" ]]; then
            [[ -n "$www_effective" && "$www_effective" =~ ^https?:// ]] && \
                base_url=$(echo "$www_effective" | grep -oE 'https?://[^/]+' || echo "$base_url")
            extract_js_from_html "$www_html" | grep -v '^$' | sort -u | while IFS= read -r ref; do
                local resolved
                resolved=$(resolve_js_url "$ref" "$base_url")
                [[ -n "$resolved" && "$resolved" =~ ^https?:// ]] && echo "$resolved"
            done >> "${RESULTS_DIR}/all_js_discovered.txt"
            parse_webpack_manifest "$base_url"
            count=$(wc -l < "${RESULTS_DIR}/all_js_discovered.txt" 2>/dev/null | tr -d '[:space:]')
            count="${count:-0}"
        fi
    fi

    # WAF/SPA fallback: Wayback CDX
    if [[ "$count" -eq 0 ]]; then
        warn "No JS found in HTML — WAF or JS-rendered SPA detected"
        info "Querying Wayback CDX for archived JS files..."
        local cdx_base="https://web.archive.org/cdx/search/cdx"
        local cdx_opts="&output=text&fl=timestamp,original&filter=statuscode:200&collapse=digest&limit=200&from=20200101"
        for pat in "*.${CLEAN_DOMAIN}/*.js" "${CLEAN_DOMAIN}/*.js" "www.${CLEAN_DOMAIN}/*.js"; do
            do_curl "${cdx_base}?url=${pat}${cdx_opts}" 2>/dev/null \
            | while read -r ts orig; do
                [[ -z "$ts" || -z "$orig" ]] && continue
                echo "https://web.archive.org/web/${ts}if_/${orig}"
            done >> "${RESULTS_DIR}/all_js_discovered.txt" || true
        done
        count=$(wc -l < "${RESULTS_DIR}/all_js_discovered.txt" 2>/dev/null | tr -d '[:space:]')
        count="${count:-0}"
        [[ "$count" -gt 0 ]] && info "Wayback CDX: $count archived JS files queued"
    fi

    # Last resort: probe well-known JS paths directly
    if [[ "$count" -eq 0 ]]; then
        info "Probing common JS paths directly..."
        local paths=("/static/js/main.js" "/static/js/bundle.js" "/assets/js/app.js"
                     "/js/main.js" "/js/app.js" "/js/bundle.js" "/app.js" "/bundle.js"
                     "/_next/static/chunks/main.js" "/dist/bundle.js" "/public/js/app.js"
                     "/static/js/index.js" "/assets/index.js" "/build/static/js/main.js")
        local probe_tmp
        probe_tmp=$(mktemp)
        for p in "${paths[@]}"; do
            local purl="${base_url}${p}"
            local http_code
            http_code=$(do_curl -o "$probe_tmp" -w "%{http_code}" "$purl" 2>/dev/null || echo "000")
            if [[ "$http_code" == "200" && -s "$probe_tmp" ]]; then
                head -c 100 "$probe_tmp" | grep -qiE '<!DOCTYPE|<html' && continue
                echo "$purl" >> "${RESULTS_DIR}/all_js_discovered.txt"
                vlog "  Direct probe found: $purl"
            fi
        done
        rm -f "$probe_tmp"
        count=$(wc -l < "${RESULTS_DIR}/all_js_discovered.txt" 2>/dev/null | tr -d '[:space:]')
        count="${count:-0}"
    fi

    sort -u "${RESULTS_DIR}/all_js_discovered.txt" -o "${RESULTS_DIR}/all_js_discovered.txt" 2>/dev/null || true
    count=$(wc -l < "${RESULTS_DIR}/all_js_discovered.txt" 2>/dev/null | tr -d '[:space:]')
    count="${count:-0}"
    ok "$count JS files queued for download from $target"
    return 0
}

# Discover JS references inside a JS file (chain discovery)
discover_js_in_js() {
    local jsfile="$1" base_url="$2" depth="${3:-0}"
    [[ "$DEEP_CRAWL" != true ]] && return
    [[ "$depth" -ge "$CHAIN_DEPTH" ]] && return
    [[ ! -f "$jsfile" ]] && return

    vlog "  ${DIM}[chain d${depth}]${NC} Scanning $(basename "$jsfile") for JS refs..."

    {
        grep -oE "require\('[^']+\.js[^']*'\)" "$jsfile" 2>/dev/null             | grep -oE "'[^']+\.js[^']*'" | tr -d "'"
        grep -oE 'require\("[^"]+\.js[^"]*"\)' "$jsfile" 2>/dev/null             | grep -oE '"[^"]+\.js[^"]*"' | tr -d '"'
        grep -oE "import\('[^']+\.js[^']*'\)" "$jsfile" 2>/dev/null              | grep -oE "'[^']+\.js[^']*'" | tr -d "'"
        grep -oE 'import\("[^"]+\.js[^"]*"\)' "$jsfile" 2>/dev/null              | grep -oE '"[^"]+\.js[^"]*"' | tr -d '"'
        grep -oE "'/[a-zA-Z0-9_/.-]+\.js'" "$jsfile" 2>/dev/null | tr -d "'"
        grep -oE '"/[a-zA-Z0-9_/.-]+\.js"' "$jsfile" 2>/dev/null | tr -d '"'
        grep -oE 'src="[^"]+\.js[^"]*"' "$jsfile" 2>/dev/null \
            | sed 's/^src="//;s/"[[:space:]]*$//'
        # Webpack chunk map: {0:"abc",1:"def"} style chunk IDs -> resolve to chunk paths
        grep -oE '"[a-f0-9]{8,20}"' "$jsfile" 2>/dev/null | tr -d '"' | while IFS= read -r chunk; do
            echo "/static/chunks/${chunk}.js"
        done
    } | grep -v '^$' | grep '\.js' | sort -u | while IFS= read -r ref; do
        local full_url
        full_url=$(resolve_js_url "$ref" "$base_url")
        [[ -z "$full_url" || ! "$full_url" =~ ^https?:// ]] && continue
        grep -qxF "$full_url" "${RESULTS_DIR}/all_js_discovered.txt" 2>/dev/null && continue
        echo "$full_url" >> "${RESULTS_DIR}/all_js_discovered.txt"
        vlog "  ${PURPLE}[chain]${NC} +$full_url"
    done
}

# Wayback Machine discovery
wayback_discovery() {
    [[ "$WAYBACK" != true ]] && return
    info "Wayback: querying historical JS snapshots..."

    local cdx="https://web.archive.org/cdx/search/cdx"
    cdx+="?url=*.${CLEAN_DOMAIN}/*.js&output=text&fl=timestamp,original"
    cdx+="&filter=statuscode:200&collapse=digest&limit=500&from=20200101"

    do_curl "$cdx" 2>/dev/null | while read -r ts orig; do
        [[ -z "$ts" || -z "$orig" ]] && continue
        echo "https://web.archive.org/web/${ts}if_/${orig}"
    done >> "${RESULTS_DIR}/all_js_discovered.txt"

    sort -u "${RESULTS_DIR}/all_js_discovered.txt" -o "${RESULTS_DIR}/all_js_discovered.txt" 2>/dev/null || true

    local wb_count
    wb_count=$(grep -c "web.archive.org" "${RESULTS_DIR}/all_js_discovered.txt" 2>/dev/null || echo 0)
    wb_count="${wb_count//[[:space:]]/}"
    wb_count="${wb_count:-0}"
    ok "Wayback: $wb_count historical snapshots queued"
}

# Parallel download
parallel_download() {
    [[ ! -f "${RESULTS_DIR}/all_js_discovered.txt" ]] && warn "No JS files discovered" && return 1

    sort -u "${RESULTS_DIR}/all_js_discovered.txt" -o "${RESULTS_DIR}/all_js_discovered.txt" 2>/dev/null || true
    local total
    total=$(wc -l < "${RESULTS_DIR}/all_js_discovered.txt" 2>/dev/null | tr -d '[:space:]')
    total="${total:-0}"
    if [[ "$total" -eq 0 ]]; then warn "No JS files to download"; return 1; fi

    info "Downloading $total unique JS files ($THREADS threads)..."

    > "${RESULTS_DIR}/logs/dl_status.txt"
    > "${RESULTS_DIR}/downloaded_files.txt"

    local dl_count=0
    local pids=()

    while IFS= read -r js_url; do
        (
            local safe
            safe=$(echo "$js_url" | sha256sum 2>/dev/null | cut -c1-12 || echo "unknown_$$")
            local outfile="${RESULTS_DIR}/js_files/${safe}.js"

            if [[ "$RESUME" == true && -f "$outfile" && -s "$outfile" ]]; then
                echo "OK" >> "${RESULTS_DIR}/logs/dl_status.txt"
                exit 0
            fi

            if do_curl -o "$outfile" "$js_url" 2>/dev/null && [[ -s "$outfile" ]]; then
                local head100
                head100=$(head -c 100 "$outfile" 2>/dev/null || true)
                if echo "$head100" | grep -qiE '<!DOCTYPE|<html'; then
                    rm -f "$outfile"
                    echo "FAIL" >> "${RESULTS_DIR}/logs/dl_status.txt"
                    exit 0
                fi
                echo "${js_url}|${safe}.js" >> "${RESULTS_DIR}/downloaded_files.txt"
                echo "OK" >> "${RESULTS_DIR}/logs/dl_status.txt"
                if [[ "$DEEP_CRAWL" == true ]]; then
                    local burl
                    burl=$(echo "$js_url" | grep -oE 'https?://[^/]+' || echo "$BASE_URL")
                    discover_js_in_js "$outfile" "$burl" 1
                fi
            else
                rm -f "$outfile"
                echo "FAIL" >> "${RESULTS_DIR}/logs/dl_status.txt"
            fi
        ) &
        pids+=($!)
        dl_count=$(( dl_count + 1 ))
        draw_progress "$dl_count" "$total" "$(basename "$js_url")"

        if [[ ${#pids[@]} -ge "$THREADS" ]]; then
            wait "${pids[@]}" 2>/dev/null || true
            pids=()
        fi
    done < "${RESULTS_DIR}/all_js_discovered.txt"

    wait "${pids[@]}" 2>/dev/null || true
    echo ""

    # Second pass: deep crawl may have added new JS URLs
    if [[ "$DEEP_CRAWL" == true ]]; then
        local new_total
        new_total=$(wc -l < "${RESULTS_DIR}/all_js_discovered.txt" 2>/dev/null | tr -d '[:space:]')
        new_total="${new_total:-0}"
        if [[ "$new_total" -gt "$total" ]]; then
            local added=$(( new_total - total ))
            info "Deep crawl found $added more JS files — downloading..."
            local new_pids=()
            tail -n "$added" "${RESULTS_DIR}/all_js_discovered.txt" | while IFS= read -r js_url; do
                (
                    local safe
                    safe=$(echo "$js_url" | sha256sum 2>/dev/null | cut -c1-12 || echo "chain_$$")
                    local outfile="${RESULTS_DIR}/js_files/${safe}.js"
                    if [[ -f "$outfile" && -s "$outfile" ]]; then
                        echo "OK" >> "${RESULTS_DIR}/logs/dl_status.txt"
                        exit 0
                    fi
                    if do_curl -o "$outfile" "$js_url" 2>/dev/null && [[ -s "$outfile" ]]; then
                        local h100
                        h100=$(head -c 100 "$outfile" 2>/dev/null || true)
                        if echo "$h100" | grep -qiE '<!DOCTYPE|<html'; then
                            rm -f "$outfile"
                            echo "FAIL" >> "${RESULTS_DIR}/logs/dl_status.txt"
                            exit 0
                        fi
                        echo "${js_url}|${safe}.js" >> "${RESULTS_DIR}/downloaded_files.txt"
                        echo "OK" >> "${RESULTS_DIR}/logs/dl_status.txt"
                    else
                        rm -f "$outfile"
                        echo "FAIL" >> "${RESULTS_DIR}/logs/dl_status.txt"
                    fi
                ) &
                new_pids+=($!)
                if [[ ${#new_pids[@]} -ge "$THREADS" ]]; then
                    wait "${new_pids[@]}" 2>/dev/null || true
                    new_pids=()
                fi
            done
            wait 2>/dev/null || true
        fi
    fi

    local ok_count fail_count
    ok_count=$(grep -c "^OK$" "${RESULTS_DIR}/logs/dl_status.txt" 2>/dev/null || echo 0)
    ok_count="${ok_count//[[:space:]]/}"
    ok_count="${ok_count:-0}"
    fail_count=$(grep -c "^FAIL$" "${RESULTS_DIR}/logs/dl_status.txt" 2>/dev/null || echo 0)
    fail_count="${fail_count//[[:space:]]/}"
    fail_count="${fail_count:-0}"
    ok "Downloaded: $ok_count   Failed: $fail_count"
    [[ "$ok_count" -eq 0 ]] && warn "Nothing downloaded" && return 1
    return 0
}

# Source map reconstruction
process_source_maps() {
    [[ "$SOURCE_MAPS" != true ]] && return
    [[ ! -f "${RESULTS_DIR}/source_map_urls.txt" ]] && return

    info "Source maps: reconstructing original source..."
    local map_count=0

    while IFS='|' read -r _origin map_url; do
        local mf_name
        mf_name=$(echo "$map_url" | sed -E 's|https?://||' | tr '/' '_')
        local map_file="${RESULTS_DIR}/source_maps/${mf_name}"
        do_curl -o "$map_file" "$map_url" 2>/dev/null || continue
        [[ ! -s "$map_file" ]] && continue
        map_count=$(( map_count + 1 ))

        python3 - "$map_file" "${RESULTS_DIR}/js_files" 2>/dev/null << 'PYEOF'
import json, sys, os, hashlib, pathlib
try:
    data = json.load(open(sys.argv[1]))
    js_dir = sys.argv[2]
    sources  = data.get('sources', [])
    contents = data.get('sourcesContent', [])
    for i, (src, content) in enumerate(zip(sources, contents or [])):
        if not content:
            continue
        name = pathlib.Path(src).name or "source_{}.js".format(i)
        name = name.replace('/', '_').replace('..', '_')
        h = hashlib.sha256(content.encode()).hexdigest()[:8]
        out = os.path.join(js_dir, "srcmap_{}_{}".format(h, name))
        open(out, 'w').write(content)
except Exception:
    pass
PYEOF
    done < "${RESULTS_DIR}/source_map_urls.txt"

    ok "$map_count source maps reconstructed"
}

# Extract endpoints from JS text
extract_endpoints() {
    local jsfile="$1"
    {
        grep -oE "'/api/[^']{2,}'" "$jsfile" 2>/dev/null | tr -d "'"
        grep -oE '"/api/[^"]{2,}"' "$jsfile" 2>/dev/null | tr -d '"'
        grep -oE "'/v[0-9]+/[^']{2,}'" "$jsfile" 2>/dev/null | tr -d "'"
        grep -oE '"/v[0-9]+/[^"]{2,}"' "$jsfile" 2>/dev/null | tr -d '"'
        grep -oE "'/graphql[^']*'" "$jsfile" 2>/dev/null | tr -d "'"
        grep -oE '"/graphql[^"]*"' "$jsfile" 2>/dev/null | tr -d '"'
        grep -oE "'/admin[^']{1,}'" "$jsfile" 2>/dev/null | tr -d "'"
        grep -oE '"/admin[^"]{1,}"' "$jsfile" 2>/dev/null | tr -d '"'
        grep -oE "'/internal[^']{1,}'" "$jsfile" 2>/dev/null | tr -d "'"
        grep -oE '"/internal[^"]{1,}"' "$jsfile" 2>/dev/null | tr -d '"'
        grep -oE "'/dashboard[^']{1,}'" "$jsfile" 2>/dev/null | tr -d "'"
        grep -oE '"/dashboard[^"]{1,}"' "$jsfile" 2>/dev/null | tr -d '"'
        grep -oE 'fetch\("[^"]{4,}"' "$jsfile" 2>/dev/null | sed 's/fetch("//;s/"$//'
        grep -oE "fetch\('[^']{4,}'" "$jsfile" 2>/dev/null | sed "s/fetch('//;s/'$//"
        grep -oE 'url: "[^"]{4,}"' "$jsfile" 2>/dev/null | sed 's/url: "//;s/"$//'
        grep -oE "url: '[^']{4,}'" "$jsfile" 2>/dev/null | sed "s/url: '//;s/'$//"
        grep -oE 'baseURL: "[^"]{4,}"' "$jsfile" 2>/dev/null | sed 's/baseURL: "//;s/"$//'
        grep -oE "baseURL: '[^']{4,}'" "$jsfile" 2>/dev/null | sed "s/baseURL: '//;s/'$//"
        grep -oE 'endpoint: "[^"]{4,}"' "$jsfile" 2>/dev/null | sed 's/endpoint: "//;s/"$//'
        grep -oE "endpoint: '[^']{4,}'" "$jsfile" 2>/dev/null | sed "s/endpoint: '//;s/'$//"
    } | grep -E '^(/|https?://)' | sort -u
}

# Safe pattern extraction
safe_extract() {
    local pattern="$1" type="$2" jsfile="$3" url="$4"
    local filename
    filename=$(basename "$jsfile")
    grep -nE "$pattern" "$jsfile" 2>/dev/null | while IFS= read -r raw; do
        local linenum="${raw%%:*}"
        local matchtext="${raw#*:}"
        local secret
        secret=$(echo "$matchtext" | grep -oE "$pattern" | head -1)
        [[ -z "$secret" ]] && continue
        local ctx=""
        if [[ -n "$linenum" && "$linenum" =~ ^[0-9]+$ ]]; then
            local start=$(( linenum > 3 ? linenum - 3 : 1 ))
            local end=$(( linenum + 3 ))
            ctx=$(sed -n "${start},${end}p" "$jsfile" 2>/dev/null | tr '\n' ' ')
        fi
        secret_emit "$type" "$secret" "$filename" "$url" "$linenum" "$ctx"
    done
}

# Main analysis — all 65+ patterns
analyze_enhanced_secrets() {
    info "Analysis: scanning with entropy >= $ENTROPY_THRESHOLD..."

    local files_count
    files_count=$(find "${RESULTS_DIR}/js_files" -type f -name "*.js" 2>/dev/null | wc -l | tr -d '[:space:]')
    files_count="${files_count:-0}"
    info "$files_count files to scan"
    echo ""

    local processed=0

    while IFS= read -r jsfile; do
        local filename
        filename=$(basename "$jsfile")
        local original_url
        original_url=$(grep "|${filename}" "${RESULTS_DIR}/downloaded_files.txt" 2>/dev/null | cut -d'|' -f1 || echo "local")

        processed=$(( processed + 1 ))
        draw_progress "$processed" "$files_count" "$filename"

        # =====================================================================
        # CLOUD
        # =====================================================================

        # --- AWS Access Key
        safe_extract 'AKIA[0-9A-Z]{16}' "AWS_ACCESS_KEY" "$jsfile" "$original_url"

        # --- AWS Secret Key
        grep -nE '(aws[_-]?secret|secretAccessKey)[^A-Za-z0-9]*[A-Za-z0-9/+]{40}' "$jsfile" 2>/dev/null | while IFS= read -r raw; do
            local ln="${raw%%:*}"
            local secret
            secret=$(echo "${raw#*:}" | grep -oE '[A-Za-z0-9/+]{40}' | head -1)
            [[ -z "$secret" ]] && continue
            # Exclude pure SHA1 hashes
            if ! echo "$secret" | grep -qE '^[a-fA-F0-9]{40}$'; then
                secret_emit "AWS_SECRET_KEY" "$secret" "$filename" "$original_url" "$ln"
            fi
        done

        # --- Google API Key
        safe_extract 'AIza[0-9A-Za-z_-]{35}' "GOOGLE_API_KEY" "$jsfile" "$original_url"

        # --- Firebase URL
        grep -nE '(firebaseio\.com|databaseURL)' "$jsfile" 2>/dev/null | while IFS= read -r raw; do
            local ln="${raw%%:*}"
            local secret
            secret=$(echo "${raw#*:}" | grep -oE 'https://[a-zA-Z0-9_-]+\.firebaseio\.com' | head -1)
            [[ -n "$secret" ]] && secret_emit "FIREBASE_URL" "$secret" "$filename" "$original_url" "$ln"
        done

        # --- Firebase API Key (firebaseConfig object)
        grep -nE 'apiKey[[:space:]]*:[[:space:]]*"AIza[0-9A-Za-z_-]{35}"' "$jsfile" 2>/dev/null | while IFS= read -r raw; do
            local ln="${raw%%:*}"
            local secret
            secret=$(echo "${raw#*:}" | grep -oE 'AIza[0-9A-Za-z_-]{35}' | head -1)
            [[ -n "$secret" ]] && secret_emit "FIREBASE_API_KEY" "$secret" "$filename" "$original_url" "$ln"
        done

        # --- Azure Storage Key
        grep -nE 'AccountKey=[A-Za-z0-9+/]{86,88}==' "$jsfile" 2>/dev/null | while IFS= read -r raw; do
            local ln="${raw%%:*}"
            local secret
            secret=$(echo "${raw#*:}" | grep -oE '[A-Za-z0-9+/]{86,88}==' | head -1)
            [[ -n "$secret" ]] && secret_emit "AZURE_STORAGE_KEY" "$secret" "$filename" "$original_url" "$ln"
        done

        # --- Azure Connection String
        grep -nE 'DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[^;]+' "$jsfile" 2>/dev/null | while IFS= read -r raw; do
            local ln="${raw%%:*}"
            local secret
            secret=$(echo "${raw#*:}" | grep -oE 'DefaultEndpointsProtocol=[^"'"'"'[:space:]]{20,}' | head -1)
            [[ -n "$secret" ]] && secret_emit "AZURE_CONN_STRING" "$secret" "$filename" "$original_url" "$ln"
        done

        # --- GCP Service Account
        grep -nE '"type"[[:space:]]*:[[:space:]]*"service_account"' "$jsfile" 2>/dev/null | while IFS= read -r raw; do
            local ln="${raw%%:*}"
            local secret
            secret=$(echo "${raw#*:}" | grep -oE '"client_email"[[:space:]]*:[[:space:]]*"[^"@]+@[^"]+\.iam\.gserviceaccount\.com"' | grep -oE '[a-z0-9_-]+@[^"]+\.iam\.gserviceaccount\.com' | head -1)
            [[ -n "$secret" ]] && secret_emit "GCP_SERVICE_ACCOUNT" "$secret" "$filename" "$original_url" "$ln"
        done
        # Also catch the private_key directly
        grep -nE '"private_key"[[:space:]]*:[[:space:]]*"-----BEGIN' "$jsfile" 2>/dev/null | while IFS= read -r raw; do
            local ln="${raw%%:*}"
            secret_emit "GCP_PRIVATE_KEY" "GCP_PRIVATE_KEY_DETECTED" "$filename" "$original_url" "$ln"
        done

        # --- DigitalOcean Token
        safe_extract 'dop_v1_[a-f0-9]{64}' "DIGITALOCEAN_TOKEN" "$jsfile" "$original_url"
        # Personal Access Token (64 hex chars after a known DO prefix pattern)
        grep -nE '(digitalocean|DO_TOKEN|do_token)[^A-Za-z0-9]*[a-f0-9]{64}' "$jsfile" 2>/dev/null | while IFS= read -r raw; do
            local ln="${raw%%:*}"
            local secret
            secret=$(echo "${raw#*:}" | grep -oE '[a-f0-9]{64}' | head -1)
            [[ -n "$secret" ]] && secret_emit "DIGITALOCEAN_TOKEN" "$secret" "$filename" "$original_url" "$ln"
        done

        # --- Heroku API Key
        grep -nE '(heroku[_-]?api[_-]?key|HEROKU_API_KEY)[^A-Za-z0-9]*[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' "$jsfile" 2>/dev/null | while IFS= read -r raw; do
            local ln="${raw%%:*}"
            local secret
            secret=$(echo "${raw#*:}" | grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' | head -1)
            [[ -n "$secret" ]] && secret_emit "HEROKU_API_KEY" "$secret" "$filename" "$original_url" "$ln"
        done

        # =====================================================================
        # VCS / CI-CD
        # =====================================================================

        # --- GitHub Token + PAT
        safe_extract 'gh[poshru]_[A-Za-z0-9_]{30,}' "GITHUB_TOKEN" "$jsfile" "$original_url"
        safe_extract 'github_pat_[A-Za-z0-9_]{82}' "GITHUB_PAT" "$jsfile" "$original_url"

        # --- GitLab Token
        safe_extract 'glpat-[A-Za-z0-9_-]{20,}' "GITLAB_TOKEN" "$jsfile" "$original_url"

        # --- npm Token
        safe_extract 'npm_[A-Za-z0-9]{30,}' "NPM_TOKEN" "$jsfile" "$original_url"

        # --- Jenkins Token
        grep -nE '(jenkins[_-]?token|JENKINS_TOKEN|jenkins[_-]?api[_-]?key)[^A-Za-z0-9]*[A-Za-z0-9]{32,}' "$jsfile" 2>/dev/null | while IFS= read -r raw; do
            local ln="${raw%%:*}"
            local secret
            secret=$(echo "${raw#*:}" | grep -oE '[A-Za-z0-9]{32,}' | tail -1)
            [[ -n "$secret" ]] && secret_emit "JENKINS_TOKEN" "$secret" "$filename" "$original_url" "$ln"
        done

        # --- Travis CI Token
        grep -nE '(travis[_-]?token|TRAVIS_TOKEN|travis[_-]?api[_-]?key)[^A-Za-z0-9]*[A-Za-z0-9_-]{20,}' "$jsfile" 2>/dev/null | while IFS= read -r raw; do
            local ln="${raw%%:*}"
            local secret
            secret=$(echo "${raw#*:}" | grep -oE '[A-Za-z0-9_-]{20,}' | tail -1)
            [[ -n "$secret" ]] && secret_emit "TRAVIS_CI_TOKEN" "$secret" "$filename" "$original_url" "$ln"
        done

        # --- CircleCI Token
        safe_extract 'circle-token=[A-Za-z0-9]{40}' "CIRCLECI_TOKEN" "$jsfile" "$original_url"
        grep -nE '(circleci[_-]?token|CIRCLE_TOKEN|CIRCLECI_API_KEY)[^A-Za-z0-9]*[A-Za-z0-9]{40}' "$jsfile" 2>/dev/null | while IFS= read -r raw; do
            local ln="${raw%%:*}"
            local secret
            secret=$(echo "${raw#*:}" | grep -oE '[A-Za-z0-9]{40}' | tail -1)
            [[ -n "$secret" ]] && secret_emit "CIRCLECI_TOKEN" "$secret" "$filename" "$original_url" "$ln"
        done

        # =====================================================================
        # PAYMENT
        # =====================================================================

        # --- Stripe Live Keys
        safe_extract '(sk|pk|rk)_live_[0-9a-zA-Z]{24,}' "STRIPE_LIVE_KEY" "$jsfile" "$original_url"

        # --- Stripe Test Keys (medium severity — still worth knowing)
        safe_extract '(sk|pk|rk)_test_[0-9a-zA-Z]{24,}' "STRIPE_TEST_KEY" "$jsfile" "$original_url"

        # --- PayPal Client ID / Secret
        grep -nE '(paypal[_-]?client[_-]?id|PAYPAL_CLIENT_ID)[^A-Za-z0-9]*[A-Za-z0-9_-]{20,}' "$jsfile" 2>/dev/null | while IFS= read -r raw; do
            local ln="${raw%%:*}"
            local secret
            secret=$(echo "${raw#*:}" | grep -oE '[A-Za-z0-9_-]{20,}' | tail -1)
            [[ -n "$secret" ]] && secret_emit "PAYPAL_CLIENT_ID" "$secret" "$filename" "$original_url" "$ln"
        done
        grep -nE '(paypal[_-]?secret|PAYPAL_SECRET|paypal[_-]?client[_-]?secret)[^A-Za-z0-9]*[A-Za-z0-9_-]{20,}' "$jsfile" 2>/dev/null | while IFS= read -r raw; do
            local ln="${raw%%:*}"
            local secret
            secret=$(echo "${raw#*:}" | grep -oE '[A-Za-z0-9_-]{20,}' | tail -1)
            [[ -n "$secret" ]] && secret_emit "PAYPAL_SECRET" "$secret" "$filename" "$original_url" "$ln"
        done

        # --- Braintree Key
        grep -nE '(braintree[_-]?key|braintree[_-]?token|BRAINTREE_KEY)[^A-Za-z0-9]*[A-Za-z0-9]{32,}' "$jsfile" 2>/dev/null | while IFS= read -r raw; do
            local ln="${raw%%:*}"
            local secret
            secret=$(echo "${raw#*:}" | grep -oE '[A-Za-z0-9]{32,}' | tail -1)
            [[ -n "$secret" ]] && secret_emit "BRAINTREE_KEY" "$secret" "$filename" "$original_url" "$ln"
        done

        # --- Shopify Admin Token
        safe_extract 'shpat_[a-fA-F0-9]{32}' "SHOPIFY_ADMIN_TOKEN" "$jsfile" "$original_url"

        # --- Shopify API Secret / Storefront Token
        safe_extract 'shpss_[a-fA-F0-9]{32}' "SHOPIFY_SHARED_SECRET" "$jsfile" "$original_url"
        safe_extract 'shpca_[a-fA-F0-9]{32}' "SHOPIFY_CUSTOM_APP_TOKEN" "$jsfile" "$original_url"
        grep -nE '(shopify[_-]?api[_-]?secret|SHOPIFY_API_SECRET)[^A-Za-z0-9]*[a-fA-F0-9]{32}' "$jsfile" 2>/dev/null | while IFS= read -r raw; do
            local ln="${raw%%:*}"
            local secret
            secret=$(echo "${raw#*:}" | grep -oE '[a-fA-F0-9]{32}' | tail -1)
            [[ -n "$secret" ]] && secret_emit "SHOPIFY_API_SECRET" "$secret" "$filename" "$original_url" "$ln"
        done

        # --- Square Access Token
        safe_extract 'sq0atp-[A-Za-z0-9_-]{22}' "SQUARE_ACCESS_TOKEN" "$jsfile" "$original_url"
        safe_extract 'sq0csp-[A-Za-z0-9_-]{43}' "SQUARE_SECRET" "$jsfile" "$original_url"

        # =====================================================================
        # COMMUNICATION
        # =====================================================================

        # --- Slack Bot/User/App Token
        safe_extract 'xox[baprs]-[0-9A-Za-z-]{10,}' "SLACK_TOKEN" "$jsfile" "$original_url"

        # --- Slack Webhook
        safe_extract 'hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[A-Za-z0-9]+' "SLACK_WEBHOOK" "$jsfile" "$original_url"

        # --- SendGrid
        safe_extract 'SG\.[A-Za-z0-9_.+-]{60,}' "SENDGRID_KEY" "$jsfile" "$original_url"

        # --- Twilio SID + Auth Token
        safe_extract 'AC[a-z0-9]{32}' "TWILIO_SID" "$jsfile" "$original_url"
        grep -nE '(authToken|auth_token)[^A-Za-z0-9]*[a-z0-9]{32}' "$jsfile" 2>/dev/null | while IFS= read -r raw; do
            local ln="${raw%%:*}"
            local secret
            secret=$(echo "${raw#*:}" | grep -oE '[a-z0-9]{32}' | tail -1)
            [[ -n "$secret" ]] && secret_emit "TWILIO_AUTH_TOKEN" "$secret" "$filename" "$original_url" "$ln"
        done

        # --- Mailgun
        safe_extract 'key-[a-z0-9]{32}' "MAILGUN_KEY" "$jsfile" "$original_url"

        # --- Mailchimp
        safe_extract '[a-f0-9]{32}-us[0-9]{1,2}' "MAILCHIMP_KEY" "$jsfile" "$original_url"

        # --- Discord Bot Token
        safe_extract '[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}' "DISCORD_BOT_TOKEN" "$jsfile" "$original_url"

        # --- Discord Webhook
        safe_extract 'discord(app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+' "DISCORD_WEBHOOK" "$jsfile" "$original_url"

        # --- Telegram Bot Token
        safe_extract '[0-9]{8,10}:[A-Za-z0-9_-]{35}' "TELEGRAM_BOT" "$jsfile" "$original_url"

        # =====================================================================
        # AI PROVIDERS
        # =====================================================================

        safe_extract 'sk-[A-Za-z0-9]{48,}' "OPENAI_KEY" "$jsfile" "$original_url"
        safe_extract 'sk-ant-[A-Za-z0-9_-]{90,}' "ANTHROPIC_KEY" "$jsfile" "$original_url"
        safe_extract 'hf_[A-Za-z0-9]{30,}' "HUGGINGFACE_TOKEN" "$jsfile" "$original_url"
        safe_extract 'r8_[A-Za-z0-9]{40}' "REPLICATE_KEY" "$jsfile" "$original_url"

        # =====================================================================
        # DATABASE
        # =====================================================================

        grep -nE '(mysql|postgresql|postgres|mongodb|redis|amqp|mongodb\+srv|cassandra|couchdb)://[^@[:space:]"'"'"']{3,}@[a-zA-Z0-9.-]+' \
            "$jsfile" 2>/dev/null | while IFS= read -r raw; do
            local ln="${raw%%:*}"
            local secret
            secret=$(echo "${raw#*:}" | grep -oE '(mysql|postgresql|postgres|mongodb|redis|amqp|mongodb\+srv|cassandra|couchdb)://[^[:space:]"'"'"'<>]{3,}' | head -1)
            [[ -n "$secret" ]] && secret_emit "DATABASE_URL" "$secret" "$filename" "$original_url" "$ln"
        done

        # =====================================================================
        # PRIVATE / SSH KEYS
        # =====================================================================

        if grep -q "BEGIN.*PRIVATE KEY\|BEGIN OPENSSH" "$jsfile" 2>/dev/null; then
            local kln
            kln=$(grep -n "BEGIN.*PRIVATE\|BEGIN OPENSSH" "$jsfile" 2>/dev/null | head -1 | cut -d: -f1)
            secret_emit "PRIVATE_KEY" "PEM_BLOCK_DETECTED" "$filename" "$original_url" "${kln:-1}"
        fi

        # =====================================================================
        # SECRETS / TOKENS
        # =====================================================================

        # --- JWT Token
        safe_extract 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' "JWT_TOKEN" "$jsfile" "$original_url"

        # --- JWT Secret (hardcoded signing secret)
        grep -nE '(jwt[_-]?secret|JWT_SECRET|jwtSecret|signing[_-]?key|SIGNING_KEY)[[:space:]]*[:=][[:space:]]*"[^"]{12,}"' "$jsfile" 2>/dev/null | while IFS= read -r raw; do
            local ln="${raw%%:*}"
            local secret
            secret=$(echo "${raw#*:}" | grep -oE '"[^"]{12,}"' | head -1 | tr -d '"')
            local ctx
            ctx=$(sed -n "$((${ln:-1} > 2 ? ${ln:-1}-2 : 1)),$((${ln:-1}+2))p" "$jsfile" 2>/dev/null | tr '\n' ' ')
            [[ -n "$secret" ]] && secret_emit "JWT_SECRET" "$secret" "$filename" "$original_url" "$ln" "$ctx"
        done

        # --- Hardcoded Passwords
        grep -nE '(password|passwd|pwd)[[:space:]]*[:=][[:space:]]*"[^"]{8,}"' "$jsfile" 2>/dev/null | while IFS= read -r raw; do
            local ln="${raw%%:*}"
            local secret
            secret=$(echo "${raw#*:}" | grep -oE '"[^"]{8,}"' | head -1 | tr -d '"')
            local ctx
            ctx=$(sed -n "$((${ln:-1} > 2 ? ${ln:-1}-2 : 1)),$((${ln:-1}+2))p" "$jsfile" 2>/dev/null | tr '\n' ' ')
            [[ -n "$secret" ]] && secret_emit "HARDCODED_PASSWORD" "$secret" "$filename" "$original_url" "$ln" "$ctx"
        done

        # --- Encryption Key
        grep -nE '(encryption[_-]?key|ENCRYPTION_KEY|aes[_-]?key|AES_KEY|cipher[_-]?key)[[:space:]]*[:=][[:space:]]*"[A-Za-z0-9+/=]{16,}"' "$jsfile" 2>/dev/null | while IFS= read -r raw; do
            local ln="${raw%%:*}"
            local secret
            secret=$(echo "${raw#*:}" | grep -oE '"[A-Za-z0-9+/=]{16,}"' | head -1 | tr -d '"')
            local ctx
            ctx=$(sed -n "$((${ln:-1} > 2 ? ${ln:-1}-2 : 1)),$((${ln:-1}+2))p" "$jsfile" 2>/dev/null | tr '\n' ' ')
            [[ -n "$secret" ]] && secret_emit "ENCRYPTION_KEY" "$secret" "$filename" "$original_url" "$ln" "$ctx"
        done

        # --- Generic Secret Key
        grep -nE '(secret[_-]?key|SECRET_KEY|app[_-]?secret|APP_SECRET)[[:space:]]*[:=][[:space:]]*"[A-Za-z0-9_\-+/=]{20,}"' "$jsfile" 2>/dev/null | while IFS= read -r raw; do
            local ln="${raw%%:*}"
            local secret
            secret=$(echo "${raw#*:}" | grep -oE '"[A-Za-z0-9_\-+/=]{20,}"' | head -1 | tr -d '"')
            local ctx
            ctx=$(sed -n "$((${ln:-1} > 2 ? ${ln:-1}-2 : 1)),$((${ln:-1}+2))p" "$jsfile" 2>/dev/null | tr '\n' ' ')
            [[ -n "$secret" ]] && secret_emit "GENERIC_SECRET_KEY" "$secret" "$filename" "$original_url" "$ln" "$ctx"
        done

        # --- Generic API Key
        grep -nE '(api[_-]?key|apikey)[[:space:]]*[:=][[:space:]]*"[A-Za-z0-9_-]{20,}"' "$jsfile" 2>/dev/null | while IFS= read -r raw; do
            local ln="${raw%%:*}"
            local secret
            secret=$(echo "${raw#*:}" | grep -oE '"[A-Za-z0-9_-]{20,}"' | head -1 | tr -d '"')
            local ctx
            ctx=$(sed -n "$((${ln:-1} > 2 ? ${ln:-1}-2 : 1)),$((${ln:-1}+2))p" "$jsfile" 2>/dev/null | tr '\n' ' ')
            [[ -n "$secret" ]] && secret_emit "GENERIC_API_KEY" "$secret" "$filename" "$original_url" "$ln" "$ctx"
        done

        # =====================================================================
        # NETWORK
        # =====================================================================

        # --- Internal IPs
        grep -nE '(10\.[0-9]{1,3}|192\.168|172\.(1[6-9]|2[0-9]|3[01]))\.[0-9]{1,3}\.[0-9]{1,3}' \
            "$jsfile" 2>/dev/null | while IFS= read -r raw; do
            local ln="${raw%%:*}"
            local secret
            secret=$(echo "${raw#*:}" | grep -oE '(10\.[0-9]{1,3}|192\.168|172\.(1[6-9]|2[0-9]|3[01]))\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
            [[ -n "$secret" ]] && secret_emit "INTERNAL_IP" "$secret" "$filename" "$original_url" "$ln"
        done

        # --- Private Subnet CIDR
        grep -nE '(10\.[0-9]{1,3}|192\.168|172\.(1[6-9]|2[0-9]|3[01]))\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}' \
            "$jsfile" 2>/dev/null | while IFS= read -r raw; do
            local ln="${raw%%:*}"
            local secret
            secret=$(echo "${raw#*:}" | grep -oE '(10\.[0-9]{1,3}|192\.168|172\.(1[6-9]|2[0-9]|3[01]))\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}' | head -1)
            [[ -n "$secret" ]] && secret_emit "PRIVATE_CIDR" "$secret" "$filename" "$original_url" "$ln"
        done

        # --- Basic Auth in URL
        grep -nE 'https?://[A-Za-z0-9_.-]+:[A-Za-z0-9_!@#$%^&*.-]{4,}@[A-Za-z0-9.-]+' \
            "$jsfile" 2>/dev/null | while IFS= read -r raw; do
            local ln="${raw%%:*}"
            local secret
            secret=$(echo "${raw#*:}" | grep -oE 'https?://[A-Za-z0-9_.-]+:[A-Za-z0-9_!@#$%^&*.-]{4,}@[A-Za-z0-9.-]+' | head -1)
            [[ -n "$secret" ]] && secret_emit "BASIC_AUTH_URL" "$secret" "$filename" "$original_url" "$ln"
        done

        # --- S3 Bucket URLs
        grep -nE '(s3://[a-z0-9_-]+|[a-z0-9_-]+\.s3\.[a-z0-9-]+\.amazonaws\.com|[a-z0-9_-]+\.s3\.amazonaws\.com)' \
            "$jsfile" 2>/dev/null | while IFS= read -r raw; do
            local ln="${raw%%:*}"
            local secret
            secret=$(echo "${raw#*:}" | grep -oE '(s3://[a-z0-9_-]+|[a-z0-9_.-]+\.s3\.[a-z0-9-]+\.amazonaws\.com|[a-z0-9_.-]+\.s3\.amazonaws\.com)' | head -1)
            [[ -n "$secret" ]] && secret_emit "S3_BUCKET_URL" "$secret" "$filename" "$original_url" "$ln"
        done

        # =====================================================================
        # AUTH / IAM
        # =====================================================================

        # --- Auth0 Client Secret
        grep -nE '(auth0[_-]?client[_-]?secret|AUTH0_CLIENT_SECRET|auth0[_-]?secret)[^A-Za-z0-9]*[A-Za-z0-9_-]{32,}' "$jsfile" 2>/dev/null | while IFS= read -r raw; do
            local ln="${raw%%:*}"
            local secret
            secret=$(echo "${raw#*:}" | grep -oE '[A-Za-z0-9_-]{32,}' | tail -1)
            [[ -n "$secret" ]] && secret_emit "AUTH0_CLIENT_SECRET" "$secret" "$filename" "$original_url" "$ln"
        done
        # Auth0 domain
        grep -nE '[a-zA-Z0-9_-]+\.auth0\.com' "$jsfile" 2>/dev/null | while IFS= read -r raw; do
            local ln="${raw%%:*}"
            local secret
            secret=$(echo "${raw#*:}" | grep -oE '[a-zA-Z0-9_-]+\.auth0\.com' | head -1)
            [[ -n "$secret" ]] && secret_emit "AUTH0_DOMAIN" "$secret" "$filename" "$original_url" "$ln"
        done

        # --- Okta API Token
        safe_extract '00[A-Za-z0-9_-]{40}' "OKTA_TOKEN" "$jsfile" "$original_url"

        # --- OAuth Client Secret
        grep -nE '(oauth[_-]?client[_-]?secret|OAUTH_CLIENT_SECRET|client_secret)[[:space:]]*[:=][[:space:]]*"[A-Za-z0-9_-]{20,}"' "$jsfile" 2>/dev/null | while IFS= read -r raw; do
            local ln="${raw%%:*}"
            local secret
            secret=$(echo "${raw#*:}" | grep -oE '"[A-Za-z0-9_-]{20,}"' | head -1 | tr -d '"')
            local ctx
            ctx=$(sed -n "$((${ln:-1} > 2 ? ${ln:-1}-2 : 1)),$((${ln:-1}+2))p" "$jsfile" 2>/dev/null | tr '\n' ' ')
            [[ -n "$secret" ]] && secret_emit "OAUTH_CLIENT_SECRET" "$secret" "$filename" "$original_url" "$ln" "$ctx"
        done

        # --- Mapbox Token
        safe_extract 'pk\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' "MAPBOX_TOKEN" "$jsfile" "$original_url"

        # =====================================================================
        # MONITORING / ANALYTICS
        # =====================================================================

        # --- Sentry DSN
        safe_extract 'https://[a-f0-9]{32}@(o[0-9]+\.)?ingest\.sentry\.io/[0-9]+' "SENTRY_DSN" "$jsfile" "$original_url"

        # --- Datadog API Key
        grep -nE '(datadog[_-]?api[_-]?key|DD_API_KEY|ddApiKey)[^A-Za-z0-9]*[a-f0-9]{32}' "$jsfile" 2>/dev/null | while IFS= read -r raw; do
            local ln="${raw%%:*}"
            local secret
            secret=$(echo "${raw#*:}" | grep -oE '[a-f0-9]{32}' | tail -1)
            [[ -n "$secret" ]] && secret_emit "DATADOG_API_KEY" "$secret" "$filename" "$original_url" "$ln"
        done

        # --- New Relic License Key
        grep -nE '(new[_-]?relic[_-]?license[_-]?key|NEW_RELIC_LICENSE_KEY|newRelicKey)[^A-Za-z0-9]*[A-Za-z0-9]{40}' "$jsfile" 2>/dev/null | while IFS= read -r raw; do
            local ln="${raw%%:*}"
            local secret
            secret=$(echo "${raw#*:}" | grep -oE '[A-Za-z0-9]{40}' | tail -1)
            [[ -n "$secret" ]] && secret_emit "NEW_RELIC_LICENSE_KEY" "$secret" "$filename" "$original_url" "$ln"
        done
        # New Relic ingest API key (NRII- prefix)
        safe_extract 'NRII-[A-Za-z0-9_-]{36,}' "NEW_RELIC_KEY" "$jsfile" "$original_url"

        # --- Amplitude API Key
        grep -nE '(amplitude[_-]?api[_-]?key|AMPLITUDE_API_KEY|amplitudeApiKey)[^A-Za-z0-9]*[a-f0-9]{32}' "$jsfile" 2>/dev/null | while IFS= read -r raw; do
            local ln="${raw%%:*}"
            local secret
            secret=$(echo "${raw#*:}" | grep -oE '[a-f0-9]{32}' | tail -1)
            [[ -n "$secret" ]] && secret_emit "AMPLITUDE_API_KEY" "$secret" "$filename" "$original_url" "$ln"
        done

        # =====================================================================
        # ENDPOINTS + SOURCE MAPS
        # =====================================================================

        extract_endpoints "$jsfile" >> "${RESULTS_DIR}/endpoints/discovered_paths.txt" 2>/dev/null || true

        if grep -q "sourceMappingURL=" "$jsfile" 2>/dev/null; then
            local map_ref
            map_ref=$(grep -oE "sourceMappingURL=[^[:space:]]+" "$jsfile" 2>/dev/null | head -1 | sed 's/sourceMappingURL=//')
            if [[ -n "$map_ref" ]]; then
                local map_url
                map_url=$(resolve_js_url "$map_ref" "$original_url")
                echo "${original_url}|${map_url}" >> "${RESULTS_DIR}/source_map_urls.txt" 2>/dev/null || true
            fi
        fi

        # =====================================================================
        # CUSTOM PATTERNS
        # =====================================================================

        if [[ -f "$CUSTOM_REGEX_FILE" && -s "$CUSTOM_REGEX_FILE" ]]; then
            while IFS='|' read -r pname pregex _pdesc; do
                [[ -z "$pname" || -z "$pregex" ]] && continue
                safe_extract "$pregex" "CUSTOM_${pname}" "$jsfile" "$original_url"
            done < "$CUSTOM_REGEX_FILE"
        fi

    done < <(find "${RESULTS_DIR}/js_files" -type f -name "*.js" 2>/dev/null)

    echo ""

    # Deduplicate findings
    if [[ -s "$SECRETS_TEMP" ]]; then
        sort -t'|' -k2,2 -u "$SECRETS_TEMP" > "${RESULTS_DIR}/findings/secrets.txt"
        local raw_count dedup_count
        raw_count=$(wc -l < "$SECRETS_TEMP" 2>/dev/null | tr -d '[:space:]')
        raw_count="${raw_count:-0}"
        dedup_count=$(wc -l < "${RESULTS_DIR}/findings/secrets.txt" 2>/dev/null | tr -d '[:space:]')
        dedup_count="${dedup_count:-0}"
        ok "$dedup_count unique findings ($((raw_count - dedup_count)) duplicates removed)"
    else
        touch "${RESULTS_DIR}/findings/secrets.txt"
        ok "No secrets found"
    fi
    rm -f "$SECRETS_TEMP"

    # Deduplicate endpoints
    if [[ -f "${RESULTS_DIR}/endpoints/discovered_paths.txt" ]]; then
        sort -u "${RESULTS_DIR}/endpoints/discovered_paths.txt" -o "${RESULTS_DIR}/endpoints/discovered_paths.txt"
        local ep_count
        ep_count=$(wc -l < "${RESULTS_DIR}/endpoints/discovered_paths.txt" 2>/dev/null | tr -d '[:space:]')
        ep_count="${ep_count:-0}"
        ok "$ep_count unique endpoints discovered"
    fi
}

# Endpoint probing with session cookies
probe_endpoints() {
    [[ "$ENDPOINT_PROBE" != true ]] && return
    [[ ! -f "${RESULTS_DIR}/endpoints/discovered_paths.txt" ]] && return

    info "Endpoint probing: fetching API routes..."

    local probe_args=()
    [[ -n "$PROBE_COOKIES" && -f "$PROBE_COOKIES" ]] && probe_args+=(-b "$PROBE_COOKIES")
    if [[ -n "$PROBE_HEADERS" && -f "$PROBE_HEADERS" ]]; then
        while IFS= read -r h; do
            [[ -n "$h" ]] && probe_args+=(-H "$h")
        done < "$PROBE_HEADERS"
    fi

    local base_url
    base_url=$(echo "$BASE_URL" | grep -oE 'https?://[^/]+' || echo "$BASE_URL")

    > "${RESULTS_DIR}/endpoints/probe_results.txt"

    head -100 "${RESULTS_DIR}/endpoints/discovered_paths.txt" | while IFS= read -r path; do
        [[ -z "$path" ]] && continue
        local full_url
        case "$path" in
            http*) full_url="$path" ;;
            *)     full_url="${base_url}${path}" ;;
        esac

        vlog "  ${DIM}[probe]${NC} $full_url"

        local resp_file
        resp_file="${RESULTS_DIR}/endpoints/resp_$(echo "$full_url" | sha256sum | cut -c1-8).txt"
        local status_code
        status_code=$(do_curl "${probe_args[@]}" -o "$resp_file" -w "%{http_code}" "$full_url" 2>/dev/null || echo "000")

        echo "${full_url}|${status_code}" >> "${RESULTS_DIR}/endpoints/probe_results.txt"
        vlog "  HTTP $status_code"

        [[ ! -s "$resp_file" ]] && continue
        local head100
        head100=$(head -c 100 "$resp_file" 2>/dev/null || true)
        echo "$head100" | grep -qiE '<!DOCTYPE|<html' && continue

        # Scan response body for secrets
        local orig_url="${full_url} [response]"
        local rfilename
        rfilename=$(basename "$resp_file")
        grep -nE 'AKIA[0-9A-Z]{16}|(sk|pk|rk)_live_[0-9a-zA-Z]{24,}|gh[poshru]_[A-Za-z0-9_]{30,}|xox[baprs]-[0-9A-Za-z-]{10,}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|AIza[0-9A-Za-z_-]{35}|SG\.[A-Za-z0-9_.+-]{60,}' \
            "$resp_file" 2>/dev/null | while IFS= read -r raw; do
            local ln="${raw%%:*}"
            local secret
            secret=$(echo "${raw#*:}" | grep -oE '[A-Za-z0-9_/+=.-]{20,}' | head -1)
            [[ -n "$secret" ]] && secret_emit "ENDPOINT_LEAK" "$secret" "$rfilename" "$orig_url" "$ln"
        done
    done

    local probe_count
    probe_count=$(wc -l < "${RESULTS_DIR}/endpoints/probe_results.txt" 2>/dev/null | tr -d '[:space:]')
    probe_count="${probe_count:-0}"
    ok "Probed $probe_count endpoints"
}

# Live credential validation
validate_credentials() {
    [[ "$VALIDATE" != true ]] && return
    [[ ! -s "${RESULTS_DIR}/findings/secrets.txt" ]] && return

    info "Validation: confirming credentials are live..."

    while IFS='|' read -r type secret _f _u _l _r _e _c; do
        case "$type" in
            AWS_ACCESS_KEY)
                local r
                r=$(do_curl -s "https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15" 2>/dev/null | head -c 300 || true)
                if echo "$r" | grep -q "UserId"; then
                    ok "${GREEN}[LIVE]${NC} AWS key: ${secret:0:20}..."
                else
                    warn "[INVALID] AWS key: ${secret:0:20}..."
                fi
                ;;
            GITHUB_TOKEN|GITHUB_PAT)
                local r
                r=$(do_curl -s "https://api.github.com/user" -H "Authorization: token $secret" 2>/dev/null | head -c 200 || true)
                if echo "$r" | grep -q '"login"'; then
                    ok "${GREEN}[LIVE]${NC} GitHub token valid"
                else
                    warn "[INVALID] GitHub token"
                fi
                ;;
            GITLAB_TOKEN)
                local r
                r=$(do_curl -s "https://gitlab.com/api/v4/user" -H "PRIVATE-TOKEN: $secret" 2>/dev/null | head -c 200 || true)
                if echo "$r" | grep -q '"id"'; then
                    ok "${GREEN}[LIVE]${NC} GitLab token valid"
                else
                    warn "[INVALID] GitLab token"
                fi
                ;;
            STRIPE_LIVE_KEY)
                local r
                r=$(do_curl -s "https://api.stripe.com/v1/account" -u "${secret}:" 2>/dev/null | head -c 200 || true)
                if echo "$r" | grep -q '"id"'; then
                    ok "${GREEN}[LIVE]${NC} Stripe key valid"
                else
                    warn "[INVALID] Stripe key"
                fi
                ;;
            OPENAI_KEY)
                local r
                r=$(do_curl -s "https://api.openai.com/v1/models" -H "Authorization: Bearer $secret" 2>/dev/null | head -c 200 || true)
                if echo "$r" | grep -q '"object"'; then
                    ok "${GREEN}[LIVE]${NC} OpenAI key valid"
                else
                    warn "[INVALID] OpenAI key"
                fi
                ;;
            ANTHROPIC_KEY)
                local r
                r=$(do_curl -s "https://api.anthropic.com/v1/models" \
                    -H "x-api-key: $secret" \
                    -H "anthropic-version: 2023-06-01" 2>/dev/null | head -c 200 || true)
                if echo "$r" | grep -q '"id"'; then
                    ok "${GREEN}[LIVE]${NC} Anthropic key valid"
                else
                    warn "[INVALID] Anthropic key"
                fi
                ;;
            HUGGINGFACE_TOKEN)
                local r
                r=$(do_curl -s "https://huggingface.co/api/whoami-v2" -H "Authorization: Bearer $secret" 2>/dev/null | head -c 200 || true)
                if echo "$r" | grep -q '"name"'; then
                    ok "${GREEN}[LIVE]${NC} HuggingFace token valid"
                else
                    warn "[INVALID] HuggingFace token"
                fi
                ;;
            SLACK_TOKEN)
                local r
                r=$(do_curl -s "https://slack.com/api/auth.test" -H "Authorization: Bearer $secret" 2>/dev/null | head -c 200 || true)
                if echo "$r" | grep -q '"ok":true'; then
                    ok "${GREEN}[LIVE]${NC} Slack token valid"
                else
                    warn "[INVALID] Slack token"
                fi
                ;;
            SENDGRID_KEY)
                local r
                r=$(do_curl -s "https://api.sendgrid.com/v3/user/account" -H "Authorization: Bearer $secret" 2>/dev/null | head -c 200 || true)
                if echo "$r" | grep -q '"username"'; then
                    ok "${GREEN}[LIVE]${NC} SendGrid key valid"
                else
                    warn "[INVALID] SendGrid key"
                fi
                ;;
            DATADOG_API_KEY)
                local r
                r=$(do_curl -s "https://api.datadoghq.com/api/v1/validate" -H "DD-API-KEY: $secret" 2>/dev/null | head -c 200 || true)
                if echo "$r" | grep -q '"valid":true'; then
                    ok "${GREEN}[LIVE]${NC} Datadog API key valid"
                else
                    warn "[INVALID] Datadog API key"
                fi
                ;;
            NPM_TOKEN)
                local r
                r=$(do_curl -s "https://registry.npmjs.org/-/whoami" -H "Authorization: Bearer $secret" 2>/dev/null | head -c 200 || true)
                if echo "$r" | grep -q '"username"'; then
                    ok "${GREEN}[LIVE]${NC} npm token valid"
                else
                    warn "[INVALID] npm token"
                fi
                ;;
            DIGITALOCEAN_TOKEN)
                local r
                r=$(do_curl -s "https://api.digitalocean.com/v2/account" -H "Authorization: Bearer $secret" 2>/dev/null | head -c 200 || true)
                if echo "$r" | grep -q '"account"'; then
                    ok "${GREEN}[LIVE]${NC} DigitalOcean token valid"
                else
                    warn "[INVALID] DigitalOcean token"
                fi
                ;;
            SHOPIFY_ADMIN_TOKEN)
                local r
                r=$(do_curl -s "https://${CLEAN_DOMAIN}/admin/api/2023-04/shop.json" -H "X-Shopify-Access-Token: $secret" 2>/dev/null | head -c 200 || true)
                if echo "$r" | grep -q '"shop"'; then
                    ok "${GREEN}[LIVE]${NC} Shopify token valid"
                else
                    warn "[INVALID] Shopify token"
                fi
                ;;
            MAPBOX_TOKEN)
                local r
                r=$(do_curl -s "https://api.mapbox.com/tokens/v2?access_token=${secret}" 2>/dev/null | head -c 200 || true)
                if echo "$r" | grep -q '"token"'; then
                    ok "${GREEN}[LIVE]${NC} Mapbox token valid"
                else
                    warn "[INVALID] Mapbox token"
                fi
                ;;
        esac
    done < "${RESULTS_DIR}/findings/secrets.txt"
}

# SARIF output
generate_sarif() {
    [[ "$SARIF_OUT" != true && "$OUTPUT_FORMAT" != "sarif" ]] && return
    local sarif_file="${RESULTS_DIR}/reports/jshawk.sarif"

    python3 - "${RESULTS_DIR}/findings/secrets.txt" "$sarif_file" "$VERSION" << 'PYEOF'
import json, sys, datetime
sf, out_file, ver = sys.argv[1], sys.argv[2], sys.argv[3]
results = []
try:
    for line in open(sf):
        p = line.strip().split('|')
        if len(p) < 6:
            continue
        t, secret, f, url, ln, risk = p[0], p[1], p[2], p[3], p[4], p[5]
        ent = p[6] if len(p) > 6 else '?'
        results.append({
            "ruleId": "JSHAWK-{}".format(t),
            "level": "error" if risk == "critical" else "warning" if risk == "high" else "note",
            "message": {"text": "{} exposed in {} (entropy: {}, risk: {})".format(t, f, ent, risk)},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": url},
                "region": {"startLine": int(ln) if ln.isdigit() else 1}
            }}],
            "partialFingerprints": {"secretHash": secret[:16]}
        })
except Exception:
    pass

sarif = {
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    "version": "2.1.0",
    "runs": [{
        "tool": {"driver": {
            "name": "JSHawk", "version": ver,
            "informationUri": "https://github.com/Mah3Sec/JSHawk",
            "rules": []
        }},
        "results": results,
        "invocations": [{"executionSuccessful": True,
                         "endTimeUtc": datetime.datetime.utcnow().isoformat() + "Z"}]
    }]
}
json.dump(sarif, open(out_file, 'w'), indent=2)
print("SARIF: {} findings -> {}".format(len(results), out_file))
PYEOF
}

# HTML report
generate_html_report() {
    [[ "$HTML_REPORT" != true && "$OUTPUT_FORMAT" != "html" ]] && return
    local html_file="${RESULTS_DIR}/reports/jshawk_report.html"

    python3 - "${RESULTS_DIR}/findings/secrets.txt" "$html_file" "$CLEAN_DOMAIN" "$VERSION" << 'PYEOF'
import sys, html as h, datetime

sf, out, domain, ver = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
findings = []
try:
    for line in open(sf):
        p = line.strip().split('|')
        if len(p) >= 6:
            findings.append(p)
except Exception:
    pass

crit = sum(1 for f in findings if len(f) > 5 and f[5] == 'critical')
high = sum(1 for f in findings if len(f) > 5 and f[5] == 'high')
med  = len(findings) - crit - high

def rc(r):
    return {'critical': '#CC0000', 'high': '#d4820f', 'medium': '#4a8fd4'}.get(r, '#7a7d9a')

rows = '\n'.join('''<tr>
<td><span style="color:{};font-weight:700">{}</span></td>
<td>{}</td>
<td><code>{}{}</code></td>
<td>{}</td>
<td><a href="{}" target="_blank" style="color:#4a8fd4">{}</a></td>
<td>{}</td>
</tr>'''.format(
    rc(f[5] if len(f) > 5 else ''),
    h.escape((f[5] if len(f) > 5 else '?').upper()),
    h.escape(f[0]),
    h.escape(f[1][:60]),
    '...' if len(f[1]) > 60 else '',
    h.escape(f[2]),
    h.escape(f[3][:80]),
    h.escape(f[3][:50]) + ('...' if len(f[3]) > 50 else ''),
    h.escape(f[4])
) for f in findings)

content = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>JSHawk - {dom}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#0D0F16;color:#C8C6D8;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;font-size:13px}}
.hdr{{background:#08000A;padding:24px 32px;border-bottom:2px solid #CC0000}}
.hdr h1{{color:#F0EEF8;font-size:22px;margin-bottom:4px}}
.hdr p{{color:#555870;font-size:12px}}
.stats{{display:flex;border-bottom:1px solid #1a1d2a}}
.stat{{flex:1;padding:20px;text-align:center;border-right:1px solid #1a1d2a}}
.stat:last-child{{border-right:none}}
.stat-n{{font-size:32px;font-weight:700;margin-bottom:4px}}
.stat-l{{font-size:11px;color:#3d4060;text-transform:uppercase;letter-spacing:.06em}}
.filter-bar{{padding:12px 16px;background:#0a0c12;border-bottom:1px solid #1a1d2a;display:flex;gap:8px}}
.filter-bar input{{background:#1a1d2a;border:1px solid #2a2d3a;color:#C8C6D8;padding:6px 10px;border-radius:4px;font-size:12px;flex:1}}
.filter-bar select{{background:#1a1d2a;border:1px solid #2a2d3a;color:#C8C6D8;padding:6px 8px;border-radius:4px;font-size:12px}}
table{{width:100%;border-collapse:collapse;font-size:12px}}
th{{background:#08000A;padding:10px 14px;text-align:left;color:#555870;font-weight:600;border-bottom:1px solid #1a1d2a;font-size:10px;text-transform:uppercase;cursor:pointer;user-select:none}}
th:hover{{color:#C8C6D8}}
td{{padding:9px 14px;border-bottom:1px solid #1a1d2a;vertical-align:top}}
tr:hover td{{background:#0f1019}}
code{{font-family:monospace;background:#1a1d2a;padding:2px 6px;border-radius:3px;font-size:11px;color:#CC0000}}
a{{color:#4a8fd4;text-decoration:none}}
a:hover{{text-decoration:underline}}
.footer{{padding:16px 32px;color:#2e3150;font-size:11px;border-top:1px solid #1a1d2a}}
.hidden{{display:none}}
</style></head><body>
<div class="hdr">
<h1>JSHawk Security Report</h1>
<p>Target: {dom} &nbsp;|&nbsp; {dt} &nbsp;|&nbsp; JSHawk v{ver}</p>
</div>
<div class="stats">
<div class="stat"><div class="stat-n" style="color:#CC0000">{crit}</div><div class="stat-l">Critical</div></div>
<div class="stat"><div class="stat-n" style="color:#d4820f">{high}</div><div class="stat-l">High</div></div>
<div class="stat"><div class="stat-n" style="color:#4a8fd4">{med}</div><div class="stat-l">Medium</div></div>
<div class="stat"><div class="stat-n" style="color:#8b7fe8">{total}</div><div class="stat-l">Total</div></div>
</div>
<div class="filter-bar">
  <input type="text" id="searchBox" placeholder="Filter by type, secret, file..." oninput="filterTable()">
  <select id="riskFilter" onchange="filterTable()">
    <option value="">All Risks</option>
    <option value="critical">Critical</option>
    <option value="high">High</option>
    <option value="medium">Medium</option>
  </select>
</div>
<table id="findings"><thead><tr>
<th onclick="sortTable(0)">Risk &#8597;</th>
<th onclick="sortTable(1)">Type &#8597;</th>
<th>Secret</th>
<th onclick="sortTable(3)">File &#8597;</th>
<th>Source URL</th>
<th>Line</th>
</tr></thead>
<tbody id="tableBody">{rows}</tbody></table>
<div class="footer">JSHawk v{ver} &mdash; github.com/Mah3Sec/JSHawk &mdash; Authorized testing only &mdash; {total} findings</div>
<script>
function filterTable(){{
  var search = document.getElementById('searchBox').value.toLowerCase();
  var risk   = document.getElementById('riskFilter').value.toLowerCase();
  var rows   = document.getElementById('tableBody').getElementsByTagName('tr');
  for(var i=0;i<rows.length;i++){{
    var text = rows[i].textContent.toLowerCase();
    var riskOk = !risk || text.indexOf(risk) > -1;
    var searchOk = !search || text.indexOf(search) > -1;
    rows[i].style.display = (riskOk && searchOk) ? '' : 'none';
  }}
}}
function sortTable(col){{
  var table = document.getElementById('tableBody');
  var rows  = Array.from(table.rows);
  rows.sort(function(a,b){{
    return a.cells[col].textContent.localeCompare(b.cells[col].textContent);
  }});
  rows.forEach(function(r){{table.appendChild(r);}});
}}
</script>
</body></html>""".format(
    dom=h.escape(domain), dt=datetime.datetime.now().strftime('%Y-%m-%d %H:%M'),
    ver=h.escape(ver), crit=crit, high=high, med=med, total=len(findings), rows=rows
)

open(out, 'w').write(content)
print("HTML: {}".format(out))
PYEOF
}

# JSON report
generate_json_report() {
    [[ "$OUTPUT_FORMAT" != "json" && "$OUTPUT_FORMAT" != "both" ]] && return
    local sf="${RESULTS_DIR}/findings/secrets.txt"
    local out="${RESULTS_DIR}/reports/jshawk.json"
    local fc="${1:-0}"

    python3 - "$sf" "$out" "$CLEAN_DOMAIN" "$VERSION" "$fc" << 'PYEOF'
import json, sys, datetime
sf, out, domain, ver, fc = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
findings = []
try:
    for line in open(sf):
        p = line.strip().split('|')
        if len(p) < 6:
            continue
        findings.append({
            "type": p[0], "secret": p[1], "file": p[2],
            "url": p[3], "line": p[4], "risk": p[5],
            "entropy": p[6] if len(p) > 6 else "?",
            "context": p[7] if len(p) > 7 else ""
        })
except Exception:
    pass

data = {
    "meta": {"tool": "JSHawk", "version": ver, "domain": domain,
             "date": datetime.datetime.utcnow().isoformat() + "Z",
             "js_files_scanned": int(fc)},
    "summary": {
        "total": len(findings),
        "critical": sum(1 for f in findings if f["risk"] == "critical"),
        "high":     sum(1 for f in findings if f["risk"] == "high"),
        "medium":   sum(1 for f in findings if f["risk"] == "medium")
    },
    "findings": findings
}
json.dump(data, open(out, 'w'), indent=2)
print("JSON: {}".format(out))
PYEOF
}

# Nuclei template export
generate_nuclei_templates() {
    [[ "$NUCLEI_EXPORT" != true ]] && return
    [[ ! -s "${RESULTS_DIR}/findings/secrets.txt" ]] && return
    info "Exporting Nuclei templates..."
    local n=0
    while IFS='|' read -r type secret _f url _l risk _e _c; do
        [[ -z "$secret" || "$secret" == "PEM_BLOCK_DETECTED" || "$secret" == "GCP_PRIVATE_KEY_DETECTED" ]] && continue
        local tfile="${RESULTS_DIR}/nuclei/jshawk_${type,,}_${secret:0:8}.yaml"
        cat > "$tfile" << YAML
id: jshawk-${type,,}-exposure
info:
  name: ${type} Exposed in JavaScript
  author: Mah3Sec
  severity: ${risk}
  tags: exposure,secrets,javascript,jshawk
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
YAML
        n=$(( n + 1 ))
    done < "${RESULTS_DIR}/findings/secrets.txt"
    ok "Generated $n Nuclei templates in: ${RESULTS_DIR}/nuclei/"
}

# Wordlist export
generate_wordlist() {
    [[ "$WORDLIST_OUT" != true ]] && return
    local wl="${RESULTS_DIR}/reports/endpoints_wordlist.txt"
    if [[ -f "${RESULTS_DIR}/endpoints/discovered_paths.txt" ]]; then
        sort -u "${RESULTS_DIR}/endpoints/discovered_paths.txt" > "$wl"
        local wlc
        wlc=$(wc -l < "$wl" 2>/dev/null | tr -d '[:space:]')
        wlc="${wlc:-0}"
        ok "Wordlist: $wl ($wlc paths)"
    fi
}

# Final summary
display_final_summary() {
    [[ "$SILENT_MODE" == true ]] && return
    local sf="${RESULTS_DIR}/findings/secrets.txt"
    local crit=0 high=0 med=0
    if [[ -s "$sf" ]]; then
        crit=$(grep -c '|critical|' "$sf" 2>/dev/null || true); crit="${crit//[[:space:]]/}"
        high=$(grep -c '|high|'     "$sf" 2>/dev/null || true); high="${high//[[:space:]]/}"
        med=$( grep -c '|medium|'   "$sf" 2>/dev/null || true); med="${med//[[:space:]]/}"
        crit=${crit:-0}; high=${high:-0}; med=${med:-0}
    fi
    echo ""
    log "${RED}${BOLD}+================================================+${NC}"
    log "${RED}${BOLD}|          JSHawk Scan Complete                  |${NC}"
    log "${RED}${BOLD}+================================================+${NC}"
    echo ""
    log "  ${BOLD}Target:${NC}    $CLEAN_DOMAIN"
    log "  ${BOLD}Findings:${NC}  ${RED}$crit critical${NC}  ${ORANGE}$high high${NC}  ${YELLOW}$med medium${NC}"
    local js_count ep_count
    js_count=$(find "${RESULTS_DIR}/js_files" -type f 2>/dev/null | wc -l | tr -d '[:space:]')
    js_count="${js_count:-0}"
    ep_count=0
    if [[ -f "${RESULTS_DIR}/endpoints/discovered_paths.txt" ]]; then
        ep_count=$(wc -l < "${RESULTS_DIR}/endpoints/discovered_paths.txt" 2>/dev/null | tr -d '[:space:]')
        ep_count="${ep_count:-0}"
    fi
    log "  ${BOLD}JS files:${NC}  $js_count scanned"
    log "  ${BOLD}Endpoints:${NC} $ep_count discovered"
    log "  ${BOLD}Results:${NC}   $RESULTS_DIR"
    echo ""
    [[ -f "${RESULTS_DIR}/scan_info.json"                  ]] && log "  Meta:     ${RESULTS_DIR}/scan_info.json"
    [[ -f "${RESULTS_DIR}/reports/jshawk.json"             ]] && log "  JSON:     ${RESULTS_DIR}/reports/jshawk.json"
    [[ -f "${RESULTS_DIR}/reports/jshawk.sarif"            ]] && log "  SARIF:    ${RESULTS_DIR}/reports/jshawk.sarif"
    [[ -f "${RESULTS_DIR}/reports/jshawk_report.html"      ]] && log "  HTML:     ${RESULTS_DIR}/reports/jshawk_report.html"
    [[ -f "${RESULTS_DIR}/reports/endpoints_wordlist.txt"  ]] && log "  Wordlist: ${RESULTS_DIR}/reports/endpoints_wordlist.txt"
    if [[ -d "${RESULTS_DIR}/nuclei" ]]; then
        ls "${RESULTS_DIR}/nuclei/"*.yaml >/dev/null 2>&1 && log "  Nuclei:   ${RESULTS_DIR}/nuclei/"
    fi
    echo ""
}

# Main
main() {
    setup_colors
    show_banner
    parse_args "$@"

    local targets=()
    [[ -n "$DOMAIN" ]] && targets+=("$DOMAIN")
    if [[ -n "$SUBDOMAIN_FILE" && -f "$SUBDOMAIN_FILE" ]]; then
        while IFS= read -r line; do
            [[ -n "$line" && ! "$line" =~ ^# ]] && targets+=("$line")
        done < "$SUBDOMAIN_FILE"
    fi

    if [[ ${#targets[@]} -eq 0 ]]; then
        err "No valid targets"
        exit 2
    fi

    local t
    for t in "${targets[@]}"; do
        if [[ -n "$SCOPE_FILE" ]]; then
            if ! grep -qF "$t" "$SCOPE_FILE" 2>/dev/null; then
                warn "Out of scope, skipping: $t"
                continue
            fi
        fi

        init_scan "$t"
        enhanced_js_discovery "$t" || true
        wayback_discovery

        if ! parallel_download; then
            err "Download phase failed for $t"
            continue
        fi

        process_source_maps
        analyze_enhanced_secrets
        probe_endpoints
        validate_credentials

        local fc
        fc=$(find "${RESULTS_DIR}/js_files" -type f 2>/dev/null | wc -l | tr -d '[:space:]')
        fc="${fc:-0}"
        generate_json_report "$fc"
        generate_sarif
        generate_html_report
        generate_nuclei_templates
        generate_wordlist
        display_final_summary
    done

    if [[ "$FINDINGS_FOUND" -gt 0 ]]; then
        exit 1
    fi
    exit 0
}

main "$@"
