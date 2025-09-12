#!/bin/bash

# JSHawk v1.0 - JavaScript Security Scanner with Source Map Support
# Fixed version with proper regex escaping

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Configuration
MAIN_RESULTS_DIR="jshawk_results"
CONFIG_DIR="$HOME/.jshawk"
CUSTOM_REGEX_FILE="$CONFIG_DIR/custom_patterns.txt"
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

mkdir -p "$CONFIG_DIR"

show_banner() {
    echo -e "${CYAN}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    JSHawk v1.0                              ║"
    echo "║           Advanced JavaScript Security Scanner              ║"
    echo "║              + Source Map Support                          ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "${YELLOW}Hunt for secrets in JavaScript files with precision${NC}"
    echo ""
}

show_help() {
    echo -e "${CYAN}Usage:${NC}"
    echo "  $0 <domain_or_url> [options]"
    echo ""
    echo -e "${CYAN}Options:${NC}"
    echo "  -t, --threads <num>        Number of concurrent downloads (default: 10)"
    echo "  -v, --verbose              Enable verbose output"
    echo "  -h, --help                 Show this help message"
    echo ""
    echo -e "${CYAN}Examples:${NC}"
    echo "  $0 example.com"
    echo "  $0 https://example.com -t 20"
    echo "  $0 example.com -v"
}

# Parse command line arguments
parse_args() {
    DOMAIN=""
    THREADS=10
    VERBOSE=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            -t|--threads)
                THREADS="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            -*)
                echo -e "${RED}Unknown option: $1${NC}"
                show_help
                exit 1
                ;;
            *)
                if [ -z "$DOMAIN" ]; then
                    DOMAIN="$1"
                else
                    echo -e "${RED}Multiple domains not supported${NC}"
                    exit 1
                fi
                shift
                ;;
        esac
    done

    if [ -z "$DOMAIN" ]; then
        echo -e "${RED}Error: Domain/URL is required${NC}"
        show_help
        exit 1
    fi
}

# Initialize scan environment
init_scan() {
    if [[ "$DOMAIN" =~ ^https?:// ]]; then
        CLEAN_DOMAIN=$(echo "$DOMAIN" | sed 's|https\?://||' | sed 's|/.*||' | sed 's|:.*||')
        BASE_URL="$DOMAIN"
    else
        CLEAN_DOMAIN="$DOMAIN"
        BASE_URL="https://$DOMAIN"
    fi

    RESULTS_DIR="$MAIN_RESULTS_DIR/${CLEAN_DOMAIN//[^a-zA-Z0-9.-]/_}_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$RESULTS_DIR"/{js_files,findings,logs,reports}

    echo -e "${BLUE}[INIT]${NC} Scan initialized"
    echo -e "${BLUE}[INFO]${NC} Domain: $CLEAN_DOMAIN"
    echo -e "${BLUE}[INFO]${NC} Results: $RESULTS_DIR"
    [ "$VERBOSE" = true ] && echo -e "${BLUE}[INFO]${NC} Threads: $THREADS"
    echo ""
}

# Enhanced JS discovery
enhanced_js_discovery() {
    local target="$1"
    local target_clean=$(echo "$target" | sed 's|https\?://||' | sed 's|/.*||')

    echo -e "${CYAN}[DISCOVERY]${NC} Processing: $target"

    local html_file="$RESULTS_DIR/temp_${target_clean//[^a-zA-Z0-9.-]/_}.html"
    local js_list="$RESULTS_DIR/temp_js_${target_clean//[^a-zA-Z0-9.-]/_}.txt"
    > "$js_list"

    # Download with error handling
    if timeout 20 curl -s -L -k -m 20 --connect-timeout 10 \
       -H "User-Agent: $USER_AGENT" \
       -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
       --max-redirs 5 \
       "$target" -o "$html_file" 2>/dev/null; then

        if [ -s "$html_file" ]; then
            local file_size=$(wc -c < "$html_file")
            echo -e "${GREEN}[SUCCESS]${NC} Downloaded $file_size bytes"
        else
            echo -e "${RED}[ERROR]${NC} Empty response from $target"
            return 1
        fi
    else
        echo -e "${RED}[ERROR]${NC} Failed to download $target"
        return 1
    fi

    # Extract JS files
    {
        grep -oE 'src=["][^"]*\.js[^"]*["]' "$html_file" 2>/dev/null | sed 's/src="//g; s/".*//g'
        grep -oE "src=['][^']*\.js[^']*[']" "$html_file" 2>/dev/null | sed "s/src='//g; s/'.*//g"
        grep -oE '["][^"]*\.js(\?[^"]*)?["]' "$html_file" 2>/dev/null | sed 's/"//g'
        grep -oE "['][^']*\.js(\?[^']*)?[']" "$html_file" 2>/dev/null | sed "s/'//g"

        # Common JS paths
        echo "/static/js/main.js"
        echo "/static/js/app.js"
        echo "/static/js/bundle.js"
        echo "/static/js/chunk.js"
        echo "/assets/js/main.js"
        echo "/assets/js/app.js"
        echo "/js/main.js"
        echo "/js/app.js"
        echo "/dist/js/app.js"
        echo "/build/static/js/main.js"

    } >> "$js_list"

    # Process and deduplicate
    sort "$js_list" | uniq | grep -E '\.js(\?|$)' > "$RESULTS_DIR/js_urls_${target_clean//[^a-zA-Z0-9.-]/_}.txt"
    local discovered_count=$(wc -l < "$RESULTS_DIR/js_urls_${target_clean//[^a-zA-Z0-9.-]/_}.txt")

    echo -e "${GREEN}[FOUND]${NC} $discovered_count unique JS files"

    # Add to global list
    while read -r js_path; do
        if [ -n "$js_path" ]; then
            echo "$target|$js_path" >> "$RESULTS_DIR/all_js_discovered.txt"
        fi
    done < "$RESULTS_DIR/js_urls_${target_clean//[^a-zA-Z0-9.-]/_}.txt"

    # Cleanup temp files
    rm -f "$html_file" "$js_list" "$RESULTS_DIR/js_urls_${target_clean//[^a-zA-Z0-9.-]/_}.txt"
}

# Source Map Discovery
discover_source_maps() {
    local target="$1"
    local target_clean=$(echo "$target" | sed 's|https\?://||' | sed 's|/.*||')

    echo -e "${CYAN}[SOURCEMAP]${NC} Discovering source maps for: $target"

    local sourcemap_list="$RESULTS_DIR/temp_sourcemaps_${target_clean//[^a-zA-Z0-9.-]/_}.txt"
    > "$sourcemap_list"

    # Check for .map files corresponding to JS files
    if [ -f "$RESULTS_DIR/js_urls_${target_clean//[^a-zA-Z0-9.-]/_}.txt" ]; then
        while read -r js_path; do
            if [ -n "$js_path" ]; then
                echo "${js_path}.map" >> "$sourcemap_list"
            fi
        done < "$RESULTS_DIR/js_urls_${target_clean//[^a-zA-Z0-9.-]/_}.txt"
    fi

    # Common source map paths
    cat >> "$sourcemap_list" << 'EOF'
/static/js/main.js.map
/static/js/app.js.map
/static/js/bundle.js.map
/static/js/chunk.js.map
/static/js/vendor.js.map
/assets/js/main.js.map
/assets/js/app.js.map
/js/main.js.map
/js/app.js.map
/js/bundle.js.map
/dist/js/app.js.map
/build/static/js/main.js.map
EOF

    sort "$sourcemap_list" | uniq > "$RESULTS_DIR/sourcemap_urls_${target_clean//[^a-zA-Z0-9.-]/_}.txt"
    local discovered_count=$(wc -l < "$RESULTS_DIR/sourcemap_urls_${target_clean//[^a-zA-Z0-9.-]/_}.txt")

    echo -e "${GREEN}[SOURCEMAP-FOUND]${NC} $discovered_count potential source map files"

    # Add to global source map list
    while read -r map_path; do
        if [ -n "$map_path" ]; then
            echo "$target|$map_path" >> "$RESULTS_DIR/all_sourcemaps_discovered.txt"
        fi
    done < "$RESULTS_DIR/sourcemap_urls_${target_clean//[^a-zA-Z0-9.-]/_}.txt"

    rm -f "$sourcemap_list" "$RESULTS_DIR/sourcemap_urls_${target_clean//[^a-zA-Z0-9.-]/_}.txt"
}

# Download files
download_files() {
    echo -e "${YELLOW}[DOWNLOAD]${NC} Starting downloads..."

    if [ ! -f "$RESULTS_DIR/all_js_discovered.txt" ]; then
        echo -e "${RED}[ERROR]${NC} No JS files to download"
        return 1
    fi

    local total_files=$(wc -l < "$RESULTS_DIR/all_js_discovered.txt")
    echo -e "${BLUE}[INFO]${NC} Downloading $total_files JS files..."

    local counter=1
    local downloaded=0

    # Download JS files
    while IFS='|' read -r base_url js_path; do
        [ -z "$js_path" ] && continue

        local js_url
        if [[ "$js_path" =~ ^https?:// ]]; then
            js_url="$js_path"
        elif [[ "$js_path" =~ ^// ]]; then
            js_url="https:$js_path"
        elif [[ "$js_path" =~ ^/ ]]; then
            js_url="$base_url$js_path"
        else
            js_url="$base_url/$js_path"
        fi

        local filename="js_file_$(printf "%04d" $counter).js"
        local filepath="$RESULTS_DIR/js_files/$filename"

        if timeout 15 curl -s -L -k -m 15 --connect-timeout 8 \
           -H "User-Agent: $USER_AGENT" \
           -H "Accept: application/javascript, text/javascript, */*" \
           --max-redirs 3 \
           "$js_url" -o "$filepath" 2>/dev/null; then

            if [ -s "$filepath" ]; then
                local size=$(wc -c < "$filepath")
                if [ $size -gt 100 ]; then
                    echo "$js_url|$filename|$size" >> "$RESULTS_DIR/downloaded_files.txt"
                    echo -e "${GREEN}[SUCCESS]${NC} $filename ($size bytes)"
                    downloaded=$((downloaded + 1))
                else
                    rm -f "$filepath"
                fi
            else
                rm -f "$filepath"
            fi
        fi

        counter=$((counter + 1))

    done < "$RESULTS_DIR/all_js_discovered.txt"

    echo -e "${GREEN}[JS DOWNLOAD COMPLETE]${NC} Downloaded: $downloaded files"

    # Download source maps if they exist
    if [ -f "$RESULTS_DIR/all_sourcemaps_discovered.txt" ]; then
        download_source_maps
    fi
}

# Download source maps
download_source_maps() {
    local map_files=$(wc -l < "$RESULTS_DIR/all_sourcemaps_discovered.txt")
    echo -e "${BLUE}[INFO]${NC} Downloading $map_files source map files..."

    local counter=1
    local downloaded_maps=0

    while IFS='|' read -r base_url map_path; do
        [ -z "$map_path" ] && continue

        local map_url
        if [[ "$map_path" =~ ^https?:// ]]; then
            map_url="$map_path"
        elif [[ "$map_path" =~ ^// ]]; then
            map_url="https:$map_path"
        elif [[ "$map_path" =~ ^/ ]]; then
            map_url="$base_url$map_path"
        else
            map_url="$base_url/$map_path"
        fi

        local filename="sourcemap_$(printf "%04d" $counter).js.map"
        local filepath="$RESULTS_DIR/js_files/$filename"

        if timeout 15 curl -s -L -k -m 15 --connect-timeout 8 \
           -H "User-Agent: $USER_AGENT" \
           -H "Accept: application/json, */*" \
           --max-redirs 3 \
           "$map_url" -o "$filepath" 2>/dev/null; then

            if [ -s "$filepath" ]; then
                local size=$(wc -c < "$filepath")
                if [ $size -gt 50 ] && grep -q '"version"' "$filepath" && grep -q '"sources"' "$filepath"; then
                    echo "$map_url|$filename|$size" >> "$RESULTS_DIR/downloaded_sourcemaps.txt"
                    echo -e "${GREEN}[SOURCEMAP-SUCCESS]${NC} $filename ($size bytes)"
                    downloaded_maps=$((downloaded_maps + 1))
                else
                    rm -f "$filepath"
                fi
            else
                rm -f "$filepath"
            fi
        fi

        counter=$((counter + 1))

    done < "$RESULTS_DIR/all_sourcemaps_discovered.txt"

    echo -e "${GREEN}[SOURCEMAP DOWNLOAD COMPLETE]${NC} Downloaded: $downloaded_maps source maps"
}

# Extract inline source maps
extract_inline_sourcemaps() {
    echo -e "${CYAN}[INLINE-MAPS]${NC} Extracting inline source maps..."

    local inline_count=0

    find "$RESULTS_DIR/js_files" -name "*.js" -type f | while read -r jsfile; do
        local filename=$(basename "$jsfile")

        if grep -q "sourceMappingURL=data:application/json" "$jsfile"; then
            local inline_map
            inline_map=$(grep -o "sourceMappingURL=data:application/json[^\"']*" "$jsfile" | head -1)

            if [[ "$inline_map" =~ base64, ]]; then
                local base64_data
                base64_data=$(echo "$inline_map" | sed 's/.*base64,//')

                local map_filename="inline_sourcemap_from_${filename}.js.map"
                local map_filepath="$RESULTS_DIR/js_files/$map_filename"

                if echo "$base64_data" | base64 -d > "$map_filepath" 2>/dev/null; then
                    if [ -s "$map_filepath" ] && grep -q '"version"' "$map_filepath"; then
                        echo "inline|$map_filename|$(wc -c < "$map_filepath")" >> "$RESULTS_DIR/downloaded_sourcemaps.txt"
                        echo -e "${GREEN}[INLINE-SUCCESS]${NC} Extracted from $filename"
                        inline_count=$((inline_count + 1))
                    else
                        rm -f "$map_filepath"
                    fi
                fi
            fi
        fi
    done

    echo -e "${GREEN}[INLINE-COMPLETE]${NC} Extracted $inline_count inline source maps"
}

# Analyze files for secrets using simple patterns
analyze_secrets() {
    echo -e "${YELLOW}[ANALYZE]${NC} Analyzing files for secrets..."

    local secrets_file="$RESULTS_DIR/findings/secrets.txt"
    > "$secrets_file"

    local files_count
    files_count=$(find "$RESULTS_DIR/js_files" -name "*.js" -o -name "*.map" | wc -l)
    echo -e "${BLUE}[INFO]${NC} Analyzing $files_count files..."

    # Process each file
    find "$RESULTS_DIR/js_files" \( -name "*.js" -o -name "*.map" \) -type f | while read -r file; do
        local filename
        filename=$(basename "$file")
        local file_type="JS"

        if [[ "$filename" == *.map ]]; then
            file_type="SOURCEMAP"
        fi

        [ "$VERBOSE" = true ] && echo -e "${CYAN}[SCAN]${NC} $filename"

        # Simple patterns that work without complex regex

        # AWS Access Keys - simple version
        grep -n "AKIA[0-9A-Z]" "$file" 2>/dev/null | while IFS=: read -r line match; do
            local secret
            secret=$(echo "$match" | grep -o "AKIA[0-9A-Z]*" | head -1)
            if [ ${#secret} -eq 20 ]; then
                echo "${file_type}_AWS_ACCESS_KEY|$secret|$filename|unknown|$line" >> "$secrets_file"
                echo -e "${RED}[${file_type}-AWS-ACCESS]${NC} $secret"
            fi
        done

        # GitHub Tokens - simple version
        grep -n "ghp_[A-Za-z0-9_]*" "$file" 2>/dev/null | while IFS=: read -r line match; do
            local secret
            secret=$(echo "$match" | grep -o "ghp_[A-Za-z0-9_]*" | head -1)
            if [ ${#secret} -eq 40 ]; then
                echo "${file_type}_GITHUB_TOKEN|$secret|$filename|unknown|$line" >> "$secrets_file"
                echo -e "${RED}[${file_type}-GITHUB]${NC} $secret"
            fi
        done

        # Google API Keys - simple version
        grep -n "AIza[0-9A-Za-z_-]*" "$file" 2>/dev/null | while IFS=: read -r line match; do
            local secret
            secret=$(echo "$match" | grep -o "AIza[0-9A-Za-z_-]*" | head -1)
            if [ ${#secret} -eq 39 ]; then
                echo "${file_type}_GOOGLE_API_KEY|$secret|$filename|unknown|$line" >> "$secrets_file"
                echo -e "${RED}[${file_type}-GOOGLE-API]${NC} $secret"
            fi
        done

        # Slack Tokens - simple version
        grep -n "xox[baprs]-[0-9a-zA-Z-]*" "$file" 2>/dev/null | while IFS=: read -r line match; do
            local secret
            secret=$(echo "$match" | grep -o "xox[baprs]-[0-9a-zA-Z-]*" | head -1)
            echo "${file_type}_SLACK_TOKEN|$secret|$filename|unknown|$line" >> "$secrets_file"
            echo -e "${RED}[${file_type}-SLACK]${NC} $secret"
        done

        # Stripe Live Keys - simple version
        grep -n "_live_[0-9a-zA-Z]*" "$file" 2>/dev/null | while IFS=: read -r line match; do
            local secret
            secret=$(echo "$match" | grep -o "[sk]k_live_[0-9a-zA-Z]*" | head -1)
            if [ -n "$secret" ] && [ ${#secret} -gt 30 ]; then
                echo "${file_type}_STRIPE_LIVE_KEY|$secret|$filename|unknown|$line" >> "$secrets_file"
                echo -e "${RED}[${file_type}-STRIPE-LIVE]${NC} $secret"
            fi
        done

        # Database URLs - simple version
        grep -n "://.*:.*@" "$file" 2>/dev/null | while IFS=: read -r line match; do
            if echo "$match" | grep -q -E "(mysql|postgres|mongodb|redis)://"; then
                local secret
                secret=$(echo "$match" | grep -o "[a-z]*://[^\"']*" | head -1)
                echo "${file_type}_DATABASE_URL|$secret|$filename|unknown|$line" >> "$secrets_file"
                echo -e "${RED}[${file_type}-DATABASE]${NC} $secret"
            fi
        done

        # Private Keys
        if grep -q "BEGIN.*PRIVATE.*KEY" "$file" 2>/dev/null; then
            local key_line
            key_line=$(grep -n "BEGIN.*PRIVATE.*KEY" "$file" | head -1 | cut -d: -f1)
            echo "${file_type}_PRIVATE_KEY|Found private key block|$filename|unknown|$key_line" >> "$secrets_file"
            echo -e "${RED}[${file_type}-PRIVATE-KEY]${NC} Found in $filename"
        fi

    done

    # Generate simple report
    if [ -f "$secrets_file" ] && [ -s "$secrets_file" ]; then
        local total_found
        total_found=$(wc -l < "$secrets_file")
        echo ""
        echo -e "${GREEN}[ANALYSIS COMPLETE]${NC} Found $total_found potential secrets!"

        # Show summary
        echo -e "${CYAN}Top findings:${NC}"
        head -10 "$secrets_file" | while IFS='|' read -r type secret file url line; do
            if [ ${#secret} -lt 50 ]; then
                echo -e "  ${RED}[$type]${NC} $secret"
            else
                echo -e "  ${RED}[$type]${NC} ${secret:0:40}..."
            fi
        done
    else
        echo -e "${YELLOW}[CLEAN]${NC} No secrets detected"
    fi
}

# Main function
main() {
    show_banner
    parse_args "$@"
    init_scan

    echo -e "${BLUE}[START]${NC} Scanning target: $CLEAN_DOMAIN"

    # Phase 1: Discovery
    echo -e "${YELLOW}[PHASE 1]${NC} Discovery"
    > "$RESULTS_DIR/all_js_discovered.txt"
    > "$RESULTS_DIR/all_sourcemaps_discovered.txt"

    enhanced_js_discovery "$BASE_URL"
    discover_source_maps "$BASE_URL"

    local total_js
    local total_sourcemaps
    total_js=$(wc -l < "$RESULTS_DIR/all_js_discovered.txt" 2>/dev/null || echo "0")
    total_sourcemaps=$(wc -l < "$RESULTS_DIR/all_sourcemaps_discovered.txt" 2>/dev/null || echo "0")

    echo -e "${BLUE}[DISCOVERY COMPLETE]${NC} Found $total_js JS files and $total_sourcemaps source maps"

    if [ "$total_js" -eq 0 ]; then
        echo -e "${RED}[ERROR]${NC} No JavaScript files discovered"
        exit 1
    fi

    # Phase 2: Download
    echo -e "${YELLOW}[PHASE 2]${NC} Download"
    download_files
    extract_inline_sourcemaps

    # Phase 3: Analysis
    echo -e "${YELLOW}[PHASE 3]${NC} Security Analysis"
    analyze_secrets

    echo ""
    echo -e "${PURPLE}${BOLD}[SCAN COMPLETE]${NC}"
    echo -e "${CYAN}Results saved to: $RESULTS_DIR${NC}"
}

# Run
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
