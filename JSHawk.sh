#!/usr/bin/env bash
# JSHawk v3.0 - Advanced JavaScript Secret Scanner
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
readonly VERSION="3.0"
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
    local sec8="${secret:0:8}"

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
    echo "  --format FORMAT          txt|json|both [default: txt]"
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
    echo -e "  ${RED}Critical:${NC} AWS Keys, Azure Storage, DB URLs, Stripe Live, Private Keys, SSH Keys, Auth0, Twilio Auth"
    echo -e "  ${YELLOW}High:${NC}     GitHub/GitLab Tokens, OpenAI, Anthropic, HuggingFace, Replicate, Slack, SendGrid, Shopify"
    echo -e "  ${YELLOW}High:${NC}     Firebase, Google API, Heroku, npm Token, Jenkins, Mailgun, Mailchimp, Discord, Telegram"
    echo -e "  ${BLUE}Medium:${NC}   JWT Token, JWT Secret, Internal IPs, Generic API Key, S3 Bucket, Sentry DSN, Mapbox, Okta"
    echo ""
    local cpcount=0; [[ -f "$CUSTOM_REGEX_FILE" ]] && cpcount=$(wc -l < "$CUSTOM_REGEX_FILE" 2>/dev/null || echo 0)
    echo -e "  ${PURPLE}Custom:${NC} $cpcount patterns in $CUSTOM_REGEX_FILE"
    echo ""
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

    # Write scan metadata
    cat > "${RESULTS_DIR}/scan_info.txt" << INFOEOF
JSHawk v${VERSION} Security Scan
================================
Domain:        $CLEAN_DOMAIN
Base URL:      $BASE_URL
Started:       $(date)
Entropy:       >= $ENTROPY_THRESHOLD
Threads:       $THREADS
Deep crawl:    $DEEP_CRAWL (depth $CHAIN_DEPTH)
Wayback:       $WAYBACK
Source maps:   $SOURCE_MAPS
Validate:      $VALIDATE
Endpoint probe:$ENDPOINT_PROBE
Diff mode:     $DIFF_MODE
INFOEOF

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
    case "$ref" in
        http*) echo "$ref" ;;
        //*)   echo "https:${ref}" ;;
        /*)    echo "${base_url%%/*}//$(echo "$base_url" | cut -d/ -f3)${ref}" ;;
        ./*)   local dir="${base_url%/*}"; echo "${dir}/${ref#./}" ;;
        ../*)  local dir="${base_url%/*}"; echo "${dir%/*}/${ref#../}" ;;
        *)     echo "${base_url%/*}/${ref}" ;;
    esac
}

# JS discovery from a page
enhanced_js_discovery() {
    local target="$1"
    local safe_name
    safe_name=$(echo "$target" | tr -cs 'a-zA-Z0-9.-' '_')
    local html_file="${RESULTS_DIR}/logs/page_${safe_name:0:60}.html"

    info "Discovery: $target"

    local attempt success=false
    for attempt in 1 2 3; do
        if do_curl -o "$html_file" "$target" 2>/dev/null && [[ -s "$html_file" ]]; then
            success=true; break
        fi
        sleep $((attempt * 2))
    done

    if [[ "$success" != true ]]; then
        warn "Could not fetch: $target"
        return 1
    fi

    local base_url
    base_url=$(echo "$target" | grep -oE 'https?://[^/]+' || echo "$BASE_URL")

    touch "${RESULTS_DIR}/all_js_discovered.txt"

    # Extract script src
    grep -oE 'src="[^"]*\.js[^"]*"' "$html_file" 2>/dev/null | sed 's/src="//;s/"//' | while read -r ref; do
        [[ -n "$ref" ]] && resolve_js_url "$ref" "$base_url"
    done >> "${RESULTS_DIR}/all_js_discovered.txt"

    grep -oE "src='[^']*\.js[^']*'" "$html_file" 2>/dev/null | sed "s/src='//;s/'//" | while read -r ref; do
        [[ -n "$ref" ]] && resolve_js_url "$ref" "$base_url"
    done >> "${RESULTS_DIR}/all_js_discovered.txt"

    # Link preload
    grep -oiE 'href="[^"]*\.js[^"]*"' "$html_file" 2>/dev/null | sed 's/href="//;s/"//' | while read -r ref; do
        [[ -n "$ref" ]] && resolve_js_url "$ref" "$base_url"
    done >> "${RESULTS_DIR}/all_js_discovered.txt"

    local count
    count=$(wc -l < "${RESULTS_DIR}/all_js_discovered.txt" 2>/dev/null || echo 0)
    ok "$count JS files discovered from $target"
    return 0
}

# Discover JS references inside a JS file (chain discovery)
discover_js_in_js() {
    local jsfile="$1" base_url="$2" depth="${3:-0}"
    [[ "$DEEP_CRAWL" != true ]] && return
    [[ "$depth" -ge "$CHAIN_DEPTH" ]] && return

    vlog "  ${DIM}[chain d${depth}]${NC} Scanning $(basename "$jsfile") for JS refs..."

    local tmp_refs="${RESULTS_DIR}/logs/.chain_refs_$$.txt"
    > "$tmp_refs"

    # import() and require()
    grep -oE "require\(['\"][^'\"]+\.js[^'\"]*['\"]" "$jsfile" 2>/dev/null \
        | grep -oE "['\"][^'\"]+\.js[^'\"]*['\"]" | tr -d "\"'" >> "$tmp_refs"
    grep -oE "import\(['\"][^'\"]+\.js[^'\"]*['\"]" "$jsfile" 2>/dev/null \
        | grep -oE "['\"][^'\"]+\.js[^'\"]*['\"]" | tr -d "\"'" >> "$tmp_refs"

    # Quoted JS paths
    grep -oE "'/[a-zA-Z0-9_/.-]+\.js'" "$jsfile" 2>/dev/null | tr -d "'" >> "$tmp_refs"
    grep -oE '"/[a-zA-Z0-9_/.-]+\.js"' "$jsfile" 2>/dev/null | tr -d '"' >> "$tmp_refs"

    # Webpack chunk hashes
    grep -oE '"[a-f0-9]{8,}"' "$jsfile" 2>/dev/null | tr -d '"' | while read -r hash; do
        echo "/static/js/${hash}.chunk.js"
        echo "/assets/${hash}.js"
    done >> "$tmp_refs"

    sort -u "$tmp_refs" | while read -r ref; do
        [[ -z "$ref" ]] && continue
        local full_url
        full_url=$(resolve_js_url "$ref" "$base_url")
        grep -qxF "$full_url" "${RESULTS_DIR}/all_js_discovered.txt" 2>/dev/null && continue
        echo "$full_url" >> "${RESULTS_DIR}/all_js_discovered.txt"
        vlog "  ${PURPLE}[chain]${NC} +$full_url"
    done

    rm -f "$tmp_refs"
}

# Wayback Machine discovery
wayback_discovery() {
    [[ "$WAYBACK" != true ]] && return
    info "Wayback: querying historical JS snapshots..."

    local cdx="https://web.archive.org/cdx/search/cdx"
    cdx+="?url=${CLEAN_DOMAIN}/*.js&output=text&fl=timestamp,original"
    cdx+="&filter=statuscode:200&collapse=digest&limit=200&from=20200101"

    do_curl "$cdx" 2>/dev/null | while read -r ts orig; do
        [[ -z "$ts" || -z "$orig" ]] && continue
        echo "https://web.archive.org/web/${ts}if_/${orig}"
    done >> "${RESULTS_DIR}/all_js_discovered.txt"

    local wb_count
    wb_count=$(grep -c "web.archive.org" "${RESULTS_DIR}/all_js_discovered.txt" 2>/dev/null || echo 0)
    ok "Wayback: $wb_count historical snapshots queued"
}

# Parallel download
parallel_download() {
    [[ ! -f "${RESULTS_DIR}/all_js_discovered.txt" ]] && warn "No JS files discovered" && return 1

    sort -u "${RESULTS_DIR}/all_js_discovered.txt" -o "${RESULTS_DIR}/all_js_discovered.txt" 2>/dev/null || true
    local total
    total=$(wc -l < "${RESULTS_DIR}/all_js_discovered.txt" 2>/dev/null || echo 0)
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

    local ok_count fail_count
    ok_count=$(grep -c "^OK$"   "${RESULTS_DIR}/logs/dl_status.txt" 2>/dev/null || echo 0)
    fail_count=$(grep -c "^FAIL$" "${RESULTS_DIR}/logs/dl_status.txt" 2>/dev/null || echo 0)
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
        out = os.path.join(js_dir, "srcmap_{}_{}" .format(h, name))
        open(out, 'w').write(content)
except Exception as e:
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
        grep -oE 'fetch\("[^"]{4,}"' "$jsfile" 2>/dev/null | sed 's/fetch("//;s/"$//'
        grep -oE "fetch\('[^']{4,}'" "$jsfile" 2>/dev/null | sed "s/fetch('//;s/'$//"
        grep -oE 'url: "[^"]{4,}"' "$jsfile" 2>/dev/null | sed 's/url: "//;s/"$//'
        grep -oE "url: '[^']{4,}'" "$jsfile" 2>/dev/null | sed "s/url: '//;s/'$//"
    } | sort -u
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

# Main analysis
analyze_enhanced_secrets() {
    info "Analysis: scanning with entropy >= $ENTROPY_THRESHOLD..."

    local files_count
    files_count=$(find "${RESULTS_DIR}/js_files" -type f -name "*.js" 2>/dev/null | wc -l || echo 0)
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

        # --- AWS
        safe_extract 'AKIA[0-9A-Z]{16}' "AWS_ACCESS_KEY" "$jsfile" "$original_url"
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

        # --- Google / Firebase
        safe_extract 'AIza[0-9A-Za-z_-]{35}' "GOOGLE_API_KEY" "$jsfile" "$original_url"
        grep -nE '(firebaseio\.com|databaseURL)' "$jsfile" 2>/dev/null | while IFS= read -r raw; do
            local ln="${raw%%:*}"
            local secret
            secret=$(echo "${raw#*:}" | grep -oE 'https://[a-zA-Z0-9_-]+\.firebaseio\.com' | head -1)
            [[ -n "$secret" ]] && secret_emit "FIREBASE_URL" "$secret" "$filename" "$original_url" "$ln"
        done

        # --- Azure
        grep -nE 'AccountKey=[A-Za-z0-9+/]{86,88}==' "$jsfile" 2>/dev/null | while IFS= read -r raw; do
            local ln="${raw%%:*}"
            local secret
            secret=$(echo "${raw#*:}" | grep -oE '[A-Za-z0-9+/]{86,88}==' | head -1)
            [[ -n "$secret" ]] && secret_emit "AZURE_STORAGE_KEY" "$secret" "$filename" "$original_url" "$ln"
        done

        # --- Stripe
        safe_extract '(sk|pk|rk)_live_[0-9a-zA-Z]{24,}' "STRIPE_LIVE_KEY" "$jsfile" "$original_url"

        # --- GitHub
        safe_extract 'gh[poshru]_[A-Za-z0-9_]{30,}' "GITHUB_TOKEN" "$jsfile" "$original_url"
        safe_extract 'github_pat_[A-Za-z0-9_]{82}' "GITHUB_PAT" "$jsfile" "$original_url"

        # --- GitLab
        safe_extract 'glpat-[A-Za-z0-9_-]{20,}' "GITLAB_TOKEN" "$jsfile" "$original_url"

        # --- npm
        safe_extract 'npm_[A-Za-z0-9]{30,}' "NPM_TOKEN" "$jsfile" "$original_url"

        # --- Slack
        safe_extract 'xox[baprs]-[0-9A-Za-z-]{10,}' "SLACK_TOKEN" "$jsfile" "$original_url"
        safe_extract 'hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[A-Za-z0-9]+' "SLACK_WEBHOOK" "$jsfile" "$original_url"

        # --- SendGrid
        safe_extract 'SG\.[A-Za-z0-9_.+-]{60,}' "SENDGRID_KEY" "$jsfile" "$original_url"

        # --- Twilio
        safe_extract 'AC[a-z0-9]{32}' "TWILIO_SID" "$jsfile" "$original_url"
        grep -nE '(authToken|auth_token)[^A-Za-z0-9]*[a-z0-9]{32}' "$jsfile" 2>/dev/null | while IFS= read -r raw; do
            local ln="${raw%%:*}"
            local secret
            secret=$(echo "${raw#*:}" | grep -oE '[a-z0-9]{32}' | tail -1)
            [[ -n "$secret" ]] && secret_emit "TWILIO_AUTH_TOKEN" "$secret" "$filename" "$original_url" "$ln"
        done

        # --- Shopify
        safe_extract 'shpat_[a-fA-F0-9]{32}' "SHOPIFY_TOKEN" "$jsfile" "$original_url"

        # --- Discord / Telegram
        safe_extract 'discord(app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+' "DISCORD_WEBHOOK" "$jsfile" "$original_url"
        safe_extract '[0-9]{8,10}:[A-Za-z0-9_-]{35}' "TELEGRAM_BOT" "$jsfile" "$original_url"

        # --- Mailgun / Mailchimp
        safe_extract 'key-[a-z0-9]{32}' "MAILGUN_KEY" "$jsfile" "$original_url"
        safe_extract '[a-f0-9]{32}-us[0-9]{1,2}' "MAILCHIMP_KEY" "$jsfile" "$original_url"

        # --- AI providers
        safe_extract 'sk-[A-Za-z0-9]{48,}' "OPENAI_KEY" "$jsfile" "$original_url"
        safe_extract 'sk-ant-[A-Za-z0-9_-]{90,}' "ANTHROPIC_KEY" "$jsfile" "$original_url"
        safe_extract 'hf_[A-Za-z0-9]{30,}' "HUGGINGFACE_TOKEN" "$jsfile" "$original_url"
        safe_extract 'r8_[A-Za-z0-9]{40}' "REPLICATE_KEY" "$jsfile" "$original_url"

        # --- Database URLs
        grep -nE '(mysql|postgresql|postgres|mongodb|redis|amqp|mongodb\+srv)://[^@[:space:]"'"'"']{3,}@[a-zA-Z0-9.-]+' \
            "$jsfile" 2>/dev/null | while IFS= read -r raw; do
            local ln="${raw%%:*}"
            local secret
            secret=$(echo "${raw#*:}" | grep -oE '(mysql|postgresql|postgres|mongodb|redis|amqp|mongodb\+srv)://[^[:space:]"'"'"'<>]{3,}' | head -1)
            [[ -n "$secret" ]] && secret_emit "DATABASE_URL" "$secret" "$filename" "$original_url" "$ln"
        done

        # --- Private keys
        if grep -q "BEGIN.*PRIVATE KEY\|BEGIN OPENSSH" "$jsfile" 2>/dev/null; then
            local kln
            kln=$(grep -n "BEGIN.*PRIVATE\|BEGIN OPENSSH" "$jsfile" 2>/dev/null | head -1 | cut -d: -f1)
            secret_emit "PRIVATE_KEY" "PEM_BLOCK_DETECTED" "$filename" "$original_url" "${kln:-1}"
        fi

        # --- JWT
        safe_extract 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' "JWT_TOKEN" "$jsfile" "$original_url"

        # --- Internal IPs
        grep -nE '(10\.[0-9]{1,3}|192\.168|172\.(1[6-9]|2[0-9]|3[01]))\.[0-9]{1,3}\.[0-9]{1,3}' \
            "$jsfile" 2>/dev/null | while IFS= read -r raw; do
            local ln="${raw%%:*}"
            local secret
            secret=$(echo "${raw#*:}" | grep -oE '(10\.[0-9]{1,3}|192\.168|172\.(1[6-9]|2[0-9]|3[01]))\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
            [[ -n "$secret" ]] && secret_emit "INTERNAL_IP" "$secret" "$filename" "$original_url" "$ln"
        done

        # --- Hardcoded passwords
        grep -nE '(password|passwd|pwd)[[:space:]]*[:=][[:space:]]*"[^"]{8,}"' "$jsfile" 2>/dev/null | while IFS= read -r raw; do
            local ln="${raw%%:*}"
            local secret
            secret=$(echo "${raw#*:}" | grep -oE '"[^"]{8,}"' | head -1 | tr -d '"')
            local ctx
            ctx=$(sed -n "$((${ln:-1} > 2 ? ${ln:-1}-2 : 1)),$((${ln:-1}+2))p" "$jsfile" 2>/dev/null | tr '\n' ' ')
            [[ -n "$secret" ]] && secret_emit "HARDCODED_PASSWORD" "$secret" "$filename" "$original_url" "$ln" "$ctx"
        done

        # --- Sentry / Mapbox / Okta
        safe_extract 'https://[a-f0-9]{32}@(o[0-9]+\.)?ingest\.sentry\.io/[0-9]+' "SENTRY_DSN" "$jsfile" "$original_url"
        safe_extract 'pk\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' "MAPBOX_TOKEN" "$jsfile" "$original_url"
        safe_extract '00[A-Za-z0-9_-]{40}' "OKTA_TOKEN" "$jsfile" "$original_url"

        # --- Generic API keys (context-gated)
        grep -nE '(api[_-]?key|apikey)[[:space:]]*[:=][[:space:]]*"[A-Za-z0-9_-]{20,}"' "$jsfile" 2>/dev/null | while IFS= read -r raw; do
            local ln="${raw%%:*}"
            local secret
            secret=$(echo "${raw#*:}" | grep -oE '"[A-Za-z0-9_-]{20,}"' | head -1 | tr -d '"')
            local ctx
            ctx=$(sed -n "$((${ln:-1} > 2 ? ${ln:-1}-2 : 1)),$((${ln:-1}+2))p" "$jsfile" 2>/dev/null | tr '\n' ' ')
            [[ -n "$secret" ]] && secret_emit "GENERIC_API_KEY" "$secret" "$filename" "$original_url" "$ln" "$ctx"
        done

        # --- Endpoints
        extract_endpoints "$jsfile" >> "${RESULTS_DIR}/endpoints/discovered_paths.txt" 2>/dev/null || true

        # --- Source map references
        if grep -q "sourceMappingURL=" "$jsfile" 2>/dev/null; then
            local map_ref
            map_ref=$(grep -oE "sourceMappingURL=[^[:space:]]+" "$jsfile" 2>/dev/null | head -1 | sed 's/sourceMappingURL=//')
            if [[ -n "$map_ref" ]]; then
                local map_url
                map_url=$(resolve_js_url "$map_ref" "$original_url")
                echo "${original_url}|${map_url}" >> "${RESULTS_DIR}/source_map_urls.txt" 2>/dev/null || true
            fi
        fi

        # --- Custom patterns
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
        raw_count=$(wc -l < "$SECRETS_TEMP" || echo 0)
        dedup_count=$(wc -l < "${RESULTS_DIR}/findings/secrets.txt" || echo 0)
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
        ep_count=$(wc -l < "${RESULTS_DIR}/endpoints/discovered_paths.txt" || echo 0)
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

    head -60 "${RESULTS_DIR}/endpoints/discovered_paths.txt" | while IFS= read -r path; do
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

        # Scan response body
        local orig_url="${full_url} [response]"
        local filename
        filename=$(basename "$resp_file")
        grep -nE 'AKIA[0-9A-Z]{16}|(sk|pk)_live_[0-9a-zA-Z]{24,}|gh[poshru]_[A-Za-z0-9_]{30,}|xox[baprs]-[0-9A-Za-z-]{10,}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' \
            "$resp_file" 2>/dev/null | while IFS= read -r raw; do
            local ln="${raw%%:*}"
            local secret
            secret=$(echo "${raw#*:}" | grep -oE '[A-Za-z0-9_/+=.-]{20,}' | head -1)
            [[ -n "$secret" ]] && secret_emit "ENDPOINT_LEAK" "$secret" "$filename" "$orig_url" "$ln"
        done
    done

    local probe_count
    probe_count=$(wc -l < "${RESULTS_DIR}/endpoints/probe_results.txt" 2>/dev/null || echo 0)
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
except Exception as e:
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
<td>{}</td>
<td>{}</td>
</tr>'''.format(
    rc(f[5] if len(f) > 5 else ''),
    h.escape((f[5] if len(f) > 5 else '?').upper()),
    h.escape(f[0]),
    h.escape(f[1][:60]),
    '...' if len(f[1]) > 60 else '',
    h.escape(f[2]),
    h.escape(f[3][:80]),
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
table{{width:100%;border-collapse:collapse;font-size:12px}}
th{{background:#08000A;padding:10px 14px;text-align:left;color:#555870;font-weight:600;border-bottom:1px solid #1a1d2a;font-size:10px;text-transform:uppercase}}
td{{padding:9px 14px;border-bottom:1px solid #1a1d2a;vertical-align:top}}
tr:hover td{{background:#0f1019}}
code{{font-family:monospace;background:#1a1d2a;padding:2px 6px;border-radius:3px;font-size:11px;color:#CC0000}}
.footer{{padding:16px 32px;color:#2e3150;font-size:11px;border-top:1px solid #1a1d2a}}
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
<table><thead><tr><th>Risk</th><th>Type</th><th>Secret</th><th>File</th><th>Source URL</th><th>Line</th></tr></thead>
<tbody>{rows}</tbody></table>
<div class="footer">JSHawk v{ver} -- github.com/Mah3Sec/JSHawk -- Authorized testing only</div>
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
        "high": sum(1 for f in findings if f["risk"] == "high"),
        "medium": sum(1 for f in findings if f["risk"] == "medium")
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
        [[ -z "$secret" || "$secret" == "PEM_BLOCK_DETECTED" ]] && continue
        local tfile="${RESULTS_DIR}/nuclei/jshawk_${type,,}_${secret:0:8}.yaml"
        cat > "$tfile" << YAML
id: jshawk-${type,,}-exposure
info:
  name: ${type} Exposed in JavaScript
  author: Mah3Sec
  severity: ${risk}
  tags: exposure,secrets,javascript
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
        ok "Wordlist: $wl ($(wc -l < "$wl" || echo 0) paths)"
    fi
}

# Final summary
display_final_summary() {
    [[ "$SILENT_MODE" == true ]] && return
    local sf="${RESULTS_DIR}/findings/secrets.txt"
    local crit=0 high=0 med=0
    if [[ -s "$sf" ]]; then
        crit=$(grep -c '|critical|' "$sf" 2>/dev/null || echo 0)
        high=$(grep -c '|high|'     "$sf" 2>/dev/null || echo 0)
        med=$(grep -c  '|medium|'   "$sf" 2>/dev/null || echo 0)
    fi
    echo ""
    log "${RED}${BOLD}+================================================+${NC}"
    log "${RED}${BOLD}|          JSHawk Scan Complete                  |${NC}"
    log "${RED}${BOLD}+================================================+${NC}"
    echo ""
    log "  ${BOLD}Target:${NC}    $CLEAN_DOMAIN"
    log "  ${BOLD}Findings:${NC}  ${RED}$crit critical${NC}  ${ORANGE}$high high${NC}  ${YELLOW}$med medium${NC}"
    local js_count ep_count
    js_count=$(find "${RESULTS_DIR}/js_files" -type f 2>/dev/null | wc -l || echo 0)
    ep_count=$(wc -l < "${RESULTS_DIR}/endpoints/discovered_paths.txt" 2>/dev/null || echo 0)
    log "  ${BOLD}JS files:${NC}  $js_count scanned"
    log "  ${BOLD}Endpoints:${NC} $ep_count discovered"
    log "  ${BOLD}Results:${NC}   $RESULTS_DIR"
    echo ""
    [[ -f "${RESULTS_DIR}/reports/jshawk.json"           ]] && log "  JSON:     ${RESULTS_DIR}/reports/jshawk.json"
    [[ -f "${RESULTS_DIR}/reports/jshawk.sarif"          ]] && log "  SARIF:    ${RESULTS_DIR}/reports/jshawk.sarif"
    [[ -f "${RESULTS_DIR}/reports/jshawk_report.html"    ]] && log "  HTML:     ${RESULTS_DIR}/reports/jshawk_report.html"
    [[ -f "${RESULTS_DIR}/reports/endpoints_wordlist.txt" ]] && log "  Wordlist: ${RESULTS_DIR}/reports/endpoints_wordlist.txt"
    [[ -d "${RESULTS_DIR}/nuclei" ]] && \
        ls "${RESULTS_DIR}/nuclei/"*.yaml >/dev/null 2>&1 && \
        log "  Nuclei:   ${RESULTS_DIR}/nuclei/"
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
        # Scope check
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
        fc=$(find "${RESULTS_DIR}/js_files" -type f 2>/dev/null | wc -l || echo 0)
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
