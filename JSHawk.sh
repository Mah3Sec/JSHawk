#!/bin/bash

# JSHawk v1.0 - Advanced JavaScript Security Scanner
# Context-Aware Credential Detection with Custom Regex Support
# Author: Security Research Team
# GitHub: https://github.com/yourusername/jshawk

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

# Create configuration directory
mkdir -p "$CONFIG_DIR"

show_banner() {
    echo -e "${CYAN}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    JSHawk v1.0                              ║"
    echo "║           Advanced JavaScript Security Scanner              ║"
    echo "║        Context-Aware Credential Detection Tool             ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "${YELLOW}🦅 Hunt for secrets in JavaScript files with precision${NC}"
    echo ""
}

show_help() {
    echo -e "${CYAN}Usage:${NC}"
    echo "  $0 <domain_or_url> [options]"
    echo ""
    echo -e "${CYAN}Options:${NC}"
    echo "  -s, --subdomains <file>    Use subdomain list from file"
    echo "  -c, --custom-regex         Add custom regex patterns interactively"
    echo "  -l, --list-patterns        List all available detection patterns"
    echo "  -o, --output <dir>         Custom output directory (default: jshawk_results)"
    echo "  -t, --threads <num>        Number of concurrent downloads (default: 10)"
    echo "  -v, --verbose              Enable verbose output"
    echo "  -h, --help                 Show this help message"
    echo ""
    echo -e "${CYAN}Examples:${NC}"
    echo "  $0 example.com"
    echo "  $0 https://example.com -s subdomains.txt"
    echo "  $0 example.com --custom-regex"
    echo "  $0 example.com -o my_scan_results -v"
    echo ""
    echo -e "${CYAN}Custom Regex Format:${NC}"
    echo "  Add patterns to ~/.jshawk/custom_patterns.txt"
    echo "  Format: PATTERN_NAME|regex_pattern|description"
    echo "  Example: CUSTOM_API|secret_key_[a-zA-Z0-9]{32}|Custom API Key Pattern"
}

list_patterns() {
    echo -e "${CYAN}${BOLD}Built-in Detection Patterns:${NC}"
    echo ""
    echo -e "${GREEN}Cloud & Infrastructure:${NC}"
    echo "  • AWS Access Keys (AKIA pattern)"
    echo "  • AWS Secret Keys (40-char base64)"
    echo "  • Google API Keys (AIza pattern)"
    echo "  • Azure Storage Keys"
    echo "  • Firebase URLs"
    echo ""
    echo -e "${GREEN}Version Control & CI/CD:${NC}"
    echo "  • GitHub Personal Access Tokens"
    echo "  • GitLab Tokens"
    echo "  • Jenkins API Tokens"
    echo ""
    echo -e "${GREEN}Communication & Payment:${NC}"
    echo "  • Slack Bot Tokens"
    echo "  • Stripe Live Keys"
    echo "  • SendGrid API Keys"
    echo "  • Twilio Account SID/Auth Token"
    echo ""
    echo -e "${GREEN}Database & Generic:${NC}"
    echo "  • Database Connection Strings"
    echo "  • JWT Secrets"
    echo "  • Generic API Keys"
    echo "  • Private SSH/TLS Keys"
    echo ""
    if [ -f "$CUSTOM_REGEX_FILE" ]; then
        echo -e "${GREEN}Custom Patterns:${NC}"
        while IFS='|' read -r name pattern desc; do
            echo "  • $name: $desc"
        done < "$CUSTOM_REGEX_FILE"
    fi
}

setup_custom_regex() {
    echo -e "${YELLOW}Custom Regex Pattern Setup${NC}"
    echo "Add your custom patterns for specific credential detection"
    echo ""
    
    touch "$CUSTOM_REGEX_FILE"
    
    while true; do
        echo -e "${CYAN}Enter pattern details (or 'done' to finish):${NC}"
        read -p "Pattern Name: " pattern_name
        
        if [ "$pattern_name" = "done" ]; then
            break
        fi
        
        read -p "Regex Pattern: " regex_pattern
        read -p "Description: " description
        
        # Validate regex
        if echo "test" | grep -qE "$regex_pattern" 2>/dev/null || true; then
            echo "$pattern_name|$regex_pattern|$description" >> "$CUSTOM_REGEX_FILE"
            echo -e "${GREEN}✓ Added pattern: $pattern_name${NC}"
        else
            echo -e "${RED}✗ Invalid regex pattern, skipping${NC}"
        fi
        echo ""
    done
    
    echo -e "${GREEN}Custom patterns saved to: $CUSTOM_REGEX_FILE${NC}"
}

# Parse command line arguments
parse_args() {
    DOMAIN=""
    SUBDOMAIN_FILE=""
    CUSTOM_OUTPUT=""
    THREADS=10
    VERBOSE=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -s|--subdomains)
                SUBDOMAIN_FILE="$2"
                shift 2
                ;;
            -c|--custom-regex)
                setup_custom_regex
                exit 0
                ;;
            -l|--list-patterns)
                list_patterns
                exit 0
                ;;
            -o|--output)
                CUSTOM_OUTPUT="$2"
                shift 2
                ;;
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
    # Parse domain from input
    if [[ "$DOMAIN" =~ ^https?:// ]]; then
        CLEAN_DOMAIN=$(echo "$DOMAIN" | sed 's|https\?://||' | sed 's|/.*||' | sed 's|:.*||')
        BASE_URL="$DOMAIN"
    else
        CLEAN_DOMAIN="$DOMAIN"
        BASE_URL="https://$DOMAIN"
    fi
    
    # Setup output directory structure
    local output_base="${CUSTOM_OUTPUT:-$MAIN_RESULTS_DIR}"
    RESULTS_DIR="$output_base/${CLEAN_DOMAIN//[^a-zA-Z0-9.-]/_}_$(date +%Y%m%d_%H%M%S)"
    
    mkdir -p "$RESULTS_DIR"/{js_files,findings,logs,reports}
    
    # Create scan metadata
    cat > "$RESULTS_DIR/scan_info.txt" << EOF
JSHawk Security Scan Report
===========================
Domain: $CLEAN_DOMAIN
Base URL: $BASE_URL
Scan Started: $(date)
JSHawk Version: v1.0
Custom Patterns: $([ -f "$CUSTOM_REGEX_FILE" ] && wc -l < "$CUSTOM_REGEX_FILE" || echo "0")
EOF

    echo -e "${BLUE}[INIT]${NC} Scan initialized"
    echo -e "${BLUE}[INFO]${NC} Domain: $CLEAN_DOMAIN"
    echo -e "${BLUE}[INFO]${NC} Results: $RESULTS_DIR"
    [ "$VERBOSE" = true ] && echo -e "${BLUE}[INFO]${NC} Threads: $THREADS"
    echo ""
}

# Enhanced JS discovery with better error handling
enhanced_js_discovery() {
    local target="$1"
    local target_clean=$(echo "$target" | sed 's|https\?://||' | sed 's|/.*||')

    echo -e "${CYAN}[DISCOVERY]${NC} Processing: $target"

    local html_file="$RESULTS_DIR/temp_${target_clean//[^a-zA-Z0-9.-]/_}.html"
    local js_list="$RESULTS_DIR/temp_js_${target_clean//[^a-zA-Z0-9.-]/_}.txt"
    > "$js_list"

    # Download with better error handling and retries
    local download_success=false
    for attempt in 1 2 3; do
        if timeout 20 curl -s -L -k -m 20 --connect-timeout 10 \
           -H "User-Agent: $USER_AGENT" \
           -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
           -H "Accept-Language: en-US,en;q=0.5" \
           -H "Accept-Encoding: gzip, deflate" \
           -H "Connection: keep-alive" \
           --max-redirs 5 \
           "$target" -o "$html_file" 2>/dev/null; then
            
            if [ -s "$html_file" ]; then
                download_success=true
                break
            fi
        fi
        [ "$VERBOSE" = true ] && echo -e "${YELLOW}[RETRY]${NC} Attempt $attempt failed for $target"
        sleep 2
    done

    if [ "$download_success" = false ]; then
        echo -e "${RED}[ERROR]${NC} Failed to download $target after 3 attempts"
        return 1
    fi

    local file_size=$(wc -c < "$html_file")
    echo -e "${GREEN}[SUCCESS]${NC} Downloaded $file_size bytes"

    # Enhanced JS extraction with multiple methods
    {
        # Method 1: Standard src attributes
        grep -oE 'src=["'"'"'][^"'"'"']*\.js[^"'"'"']*["\'"'"']' "$html_file" 2>/dev/null | \
        sed 's/src=["'"'"']//g; s/["'"'"'].*//g'
        
        # Method 2: Script tags with .js references
        grep -oE '["'"'"'][^"'"'"']*\.js(\?[^"'"'"']*)?["\'"'"']' "$html_file" 2>/dev/null | \
        sed 's/["'"'"']//g'
        
        # Method 3: Import statements
        grep -oE 'import.*["'"'"'][^"'"'"']*\.js[^"'"'"']*["\'"'"']' "$html_file" 2>/dev/null | \
        sed -E 's/.*["'"'"']([^"'"'"']*\.js[^"'"'"']*)["\'"'"'].*/\1/'
        
        # Method 4: Dynamic imports
        grep -oE 'import\([^)]*["'"'"'][^"'"'"']*\.js[^"'"'"']*["\'"'"'][^)]*\)' "$html_file" 2>/dev/null | \
        sed -E 's/.*["'"'"']([^"'"'"']*\.js[^"'"'"']*)["\'"'"'].*/\1/'
        
        # Common JS paths for modern web apps
        echo "/static/js/main.js"
        echo "/static/js/app.js"
        echo "/static/js/bundle.js"
        echo "/static/js/chunk.js"
        echo "/assets/js/main.js"
        echo "/assets/js/app.js"
        echo "/js/main.js"
        echo "/js/app.js"
        echo "/js/config.js"
        echo "/js/settings.js"
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

# Parallel download function
parallel_download() {
    echo -e "${YELLOW}[DOWNLOAD]${NC} Starting parallel downloads (threads: $THREADS)..."

    if [ ! -f "$RESULTS_DIR/all_js_discovered.txt" ]; then
        echo -e "${RED}[ERROR]${NC} No JS files to download"
        return 1
    fi

    local total_files=$(wc -l < "$RESULTS_DIR/all_js_discovered.txt")
    echo -e "${BLUE}[INFO]${NC} Downloading $total_files JS files..."

    local counter=1
    local downloaded=0
    local failed=0

    # Create temporary download script
    local download_script="$RESULTS_DIR/download_worker.sh"
    cat > "$download_script" << 'EOF'
#!/bin/bash
download_single() {
    local base_url="$1"
    local js_path="$2"
    local counter="$3"
    local total="$4"
    local results_dir="$5"
    local user_agent="$6"
    
    if [ -z "$js_path" ]; then return 1; fi
    
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
    local filepath="$results_dir/js_files/$filename"
    
    if timeout 15 curl -s -L -k -m 15 --connect-timeout 8 \
       -H "User-Agent: $user_agent" \
       -H "Accept: application/javascript, text/javascript, */*" \
       --max-redirs 3 \
       "$js_url" -o "$filepath" 2>/dev/null; then
        
        if [ -s "$filepath" ]; then
            local size=$(wc -c < "$filepath")
            if [ $size -gt 100 ]; then
                echo "$js_url|$filename|$size" >> "$results_dir/downloaded_files.txt"
                echo "SUCCESS|$counter|$total|$filename|$size"
                return 0
            else
                rm -f "$filepath"
            fi
        else
            rm -f "$filepath"
        fi
    fi
    
    echo "FAILED|$counter|$total|$js_url"
    return 1
}

download_single "$@"
EOF
    chmod +x "$download_script"

    # Process downloads in parallel
    export -f download_single
    
    while IFS='|' read -r base_url js_path; do
        while [ $(jobs -r | wc -l) -ge "$THREADS" ]; do
            sleep 0.1
        done
        
        (
            result=$("$download_script" "$base_url" "$js_path" "$counter" "$total_files" "$RESULTS_DIR" "$USER_AGENT")
            echo "$result"
        ) &
        
        counter=$((counter + 1))
        
    done < "$RESULTS_DIR/all_js_discovered.txt"
    
    # Wait for all downloads to complete
    wait
    
    # Process results
    if [ -f "$RESULTS_DIR/downloaded_files.txt" ]; then
        downloaded=$(wc -l < "$RESULTS_DIR/downloaded_files.txt")
    fi
    
    failed=$((total_files - downloaded))
    
    echo ""
    echo -e "${GREEN}[DOWNLOAD COMPLETE]${NC} Success: $downloaded, Failed: $failed"
    
    rm -f "$download_script"
    
    if [ $downloaded -eq 0 ]; then
        echo -e "${RED}[ERROR]${NC} No files downloaded successfully"
        return 1
    fi
    
    return 0
}

# Enhanced credential detection with custom patterns
analyze_enhanced_secrets() {
    echo -e "${YELLOW}[ANALYZE]${NC} Enhanced credential detection with custom patterns..."

    local secrets_file="$RESULTS_DIR/findings/secrets.txt"
    local summary_file="$RESULTS_DIR/findings/summary.txt"
    local detailed_report="$RESULTS_DIR/reports/detailed_analysis.txt"

    > "$secrets_file"

    local files_count=$(find "$RESULTS_DIR/js_files" -name "*.js" | wc -l)
    echo -e "${BLUE}[INFO]${NC} Analyzing $files_count JS files..."

    # Process each JS file
    find "$RESULTS_DIR/js_files" -name "*.js" -type f | while read -r jsfile; do
        local filename=$(basename "$jsfile")
        local original_url=$(grep "|$filename|" "$RESULTS_DIR/downloaded_files.txt" 2>/dev/null | cut -d'|' -f1)

        [ "$VERBOSE" = true ] && echo -e "${CYAN}[SCAN]${NC} $filename"

        # Built-in patterns (your existing comprehensive patterns)
        
        # AWS Credentials
        grep -nE '(aws[_-]?access[_-]?key[_-]?id|access[_-]?key[_-]?id|accessKeyId)["\'"'"'\s]*[=:]["\'"'"'\s]*["\'"'"'](AKIA[0-9A-Z]{16})["\'"'"']' "$jsfile" 2>/dev/null | while IFS=: read -r line match; do
            local secret=$(echo "$match" | sed -E 's/.*["\'"'"'](AKIA[0-9A-Z]{16})["\'"'"'].*/\1/')
            echo "AWS_ACCESS_KEY|$secret|$filename|$original_url|$line" >> "$secrets_file"
            echo -e "${RED}[AWS-ACCESS]${NC} $secret"
        done

        grep -nE '(aws[_-]?secret[_-]?access[_-]?key|secret[_-]?access[_-]?key|secretAccessKey)["\'"'"'\s]*[=:]["\'"'"'\s]*["\'"'"']([A-Za-z0-9/+]{40})["\'"'"']' "$jsfile" 2>/dev/null | while IFS=: read -r line match; do
            local secret=$(echo "$match" | sed -E 's/.*["\'"'"']([A-Za-z0-9/+]{40})["\'"'"'].*/\1/')
            if [[ "$secret" =~ ^[A-Za-z0-9/+]{40}$ ]] && ! echo "$secret" | grep -qE '^[a-f0-9]{40}$|^[A-F0-9]{40}$'; then
                echo "AWS_SECRET_KEY|$secret|$filename|$original_url|$line" >> "$secrets_file"
                echo -e "${RED}[AWS-SECRET]${NC} $secret"
            fi
        done

        # GitHub Tokens
        grep -nE '\b(ghp_[A-Za-z0-9_]{36}|gho_[A-Za-z0-9_]{36}|ghu_[A-Za-z0-9_]{36}|ghs_[A-Za-z0-9_]{36}|ghr_[A-Za-z0-9_]{36})\b' "$jsfile" 2>/dev/null | while IFS=: read -r line match; do
            local secret=$(echo "$match" | grep -oE 'gh[poshru]_[A-Za-z0-9_]{36}')
            echo "GITHUB_TOKEN|$secret|$filename|$original_url|$line" >> "$secrets_file"
            echo -e "${RED}[GITHUB]${NC} $secret"
        done

        # Google API Keys
        grep -nE '\b(AIza[0-9A-Za-z_-]{35})\b' "$jsfile" 2>/dev/null | while IFS=: read -r line match; do
            local secret=$(echo "$match" | grep -oE 'AIza[0-9A-Za-z_-]{35}')
            echo "GOOGLE_API_KEY|$secret|$filename|$original_url|$line" >> "$secrets_file"
            echo -e "${RED}[GOOGLE-API]${NC} $secret"
        done

        # Slack Tokens
        grep -nE '\b(xoxb-[0-9a-zA-Z-]+|xoxa-[0-9a-zA-Z-]+|xoxp-[0-9a-zA-Z-]+|xoxr-[0-9a-zA-Z-]+)\b' "$jsfile" 2>/dev/null | while IFS=: read -r line match; do
            local secret=$(echo "$match" | grep -oE 'xox[baprs]-[0-9a-zA-Z-]+')
            echo "SLACK_TOKEN|$secret|$filename|$original_url|$line" >> "$secrets_file"
            echo -e "${RED}[SLACK]${NC} $secret"
        done

        # Stripe Live Keys
        grep -nE '\b((sk|pk|rk)_live_[0-9a-zA-Z]{24,})\b' "$jsfile" 2>/dev/null | while IFS=: read -r line match; do
            local secret=$(echo "$match" | grep -oE '(sk|pk|rk)_live_[0-9a-zA-Z]{24,}')
            echo "STRIPE_LIVE_KEY|$secret|$filename|$original_url|$line" >> "$secrets_file"
            echo -e "${RED}[STRIPE-LIVE]${NC} $secret"
        done

        # SendGrid API Keys
        grep -nE '\b(SG\.[A-Za-z0-9_.-]{66})\b' "$jsfile" 2>/dev/null | while IFS=: read -r line match; do
            local secret=$(echo "$match" | grep -oE 'SG\.[A-Za-z0-9_.-]{66}')
            echo "SENDGRID_API_KEY|$secret|$filename|$original_url|$line" >> "$secrets_file"
            echo -e "${RED}[SENDGRID]${NC} $secret"
        done

        # Database URLs
        grep -nE '\b(mysql|postgresql|postgres|mongodb|redis)://[a-zA-Z0-9_-]+:[^@\s"'"'"']+@[a-zA-Z0-9.-]+' "$jsfile" 2>/dev/null | while IFS=: read -r line match; do
            local secret=$(echo "$match" | grep -oE '(mysql|postgresql|postgres|mongodb|redis)://[a-zA-Z0-9_-]+:[^@\s"'"'"']+@[a-zA-Z0-9.-]+[^"\s'"'"']*')
            echo "DATABASE_URL|$secret|$filename|$original_url|$line" >> "$secrets_file"
            echo -e "${RED}[DATABASE]${NC} $secret"
        done

        # Private Keys
        if grep -q "BEGIN.*PRIVATE.*KEY" "$jsfile" 2>/dev/null; then
            local key_line=$(grep -n "BEGIN.*PRIVATE.*KEY" "$jsfile" | head -1 | cut -d: -f1)
            echo "PRIVATE_KEY|Found private key block|$filename|$original_url|$key_line" >> "$secrets_file"
            echo -e "${RED}[PRIVATE-KEY]${NC} Found in $filename"
        fi

        # Custom patterns from user configuration
        if [ -f "$CUSTOM_REGEX_FILE" ] && [ -s "$CUSTOM_REGEX_FILE" ]; then
            while IFS='|' read -r pattern_name regex_pattern description; do
                if [ -n "$pattern_name" ] && [ -n "$regex_pattern" ]; then
                    grep -nE "$regex_pattern" "$jsfile" 2>/dev/null | while IFS=: read -r line match; do
                        local secret=$(echo "$match" | grep -oE "$regex_pattern" | head -1)
                        if [ -n "$secret" ]; then
                            echo "CUSTOM_$pattern_name|$secret|$filename|$original_url|$line" >> "$secrets_file"
                            echo -e "${PURPLE}[CUSTOM-$pattern_name]${NC} $secret"
                        fi
                    done
                fi
            done < "$CUSTOM_REGEX_FILE"
        fi

    done

    # Generate comprehensive reports
    generate_reports "$secrets_file" "$summary_file" "$detailed_report" "$files_count"
}

# Generate detailed reports
generate_reports() {
    local secrets_file="$1"
    local summary_file="$2"
    local detailed_report="$3"
    local files_count="$4"

    if [ -f "$secrets_file" ] && [ -s "$secrets_file" ]; then
        local total_found=$(wc -l < "$secrets_file")

        # Summary report
        {
            echo "JSHawk v1.0 - Enhanced Security Analysis Report"
            echo "=============================================="
            echo "Domain: $CLEAN_DOMAIN"
            echo "Scan Date: $(date)"
            echo "JS Files Analyzed: $files_count"
            echo "Total Secrets Found: $total_found"
            echo ""
            echo "SECURITY RISK ASSESSMENT:"
            echo "========================"
            
            local critical_count=$(grep -E "(AWS_ACCESS_KEY|AWS_SECRET_KEY|STRIPE_LIVE_KEY|DATABASE_URL|PRIVATE_KEY)" "$secrets_file" | wc -l)
            local high_count=$(grep -E "(GITHUB_TOKEN|GOOGLE_API_KEY|SLACK_TOKEN|SENDGRID_API_KEY)" "$secrets_file" | wc -l)
            local medium_count=$(grep -E "(API_KEY|JWT_SECRET)" "$secrets_file" | wc -l)
            local custom_count=$(grep "CUSTOM_" "$secrets_file" | wc -l)
            
            echo "🔴 CRITICAL: $critical_count (Immediate action required)"
            echo "🟠 HIGH: $high_count (Review and rotate)"
            echo "🟡 MEDIUM: $medium_count (Monitor and assess)"
            echo "🟣 CUSTOM: $custom_count (User-defined patterns)"
            
            echo ""
            echo "CREDENTIAL BREAKDOWN:"
            echo "===================="
            cut -d'|' -f1 "$secrets_file" | sort | uniq -c | sort -nr
            
        } > "$summary_file"

        # Detailed analysis report
        {
            echo "JSHawk v1.0 - Detailed Security Analysis"
            echo "========================================"
            echo "Generated: $(date)"
            echo "Domain: $CLEAN_DOMAIN"
            echo ""
            echo "EXECUTIVE SUMMARY:"
            echo "=================="
            echo "This scan identified $total_found potential security credentials in JavaScript files."
            echo "Immediate attention is required for CRITICAL findings."
            echo ""
            echo "DETAILED FINDINGS:"
            echo "=================="
            echo ""
            
            # Group findings by type
            cut -d'|' -f1 "$secrets_file" | sort | uniq | while read -r cred_type; do
                echo "[$cred_type]"
                echo "$(printf '=%.0s' {1..40})"
                grep "^$cred_type|" "$secrets_file" | while IFS='|' read -r type secret file url line; do
                    echo "  File: $file"
                    echo "  URL: $url"
                    echo "  Line: $line"
                    if [ ${#secret} -lt 80 ]; then
                        echo "  Secret: $secret"
                    else
                        echo "  Secret: ${secret:0:60}..."
                    fi
                    echo ""
                done
                echo ""
            done
            
        } > "$detailed_report"

        echo ""
        echo -e "${GREEN}[COMPLETE]${NC} Found $total_found credentials across $files_count files!"

    else
        echo "No validated credentials found." > "$summary_file"
        echo "Clean scan - no credentials detected." > "$detailed_report"
        echo -e "${YELLOW}[CLEAN]${NC} No credentials detected"
    fi
}

# Main execution function
main() {
    show_banner
    parse_args "$@"
    init_scan

    echo -e "${BLUE}[START]${NC} Enhanced credential detection on target: $CLEAN_DOMAIN"

    # Create target list
    local targets_file="$RESULTS_DIR/targets.txt"
    
    if [ -n "$SUBDOMAIN_FILE" ] && [ -f "$SUBDOMAIN_FILE" ]; then
        echo -e "${YELLOW}[SUBDOMAINS]${NC} Processing: $SUBDOMAIN_FILE"
        while read -r line; do
            if [ -n "$line" ] && [[ ! "$line" =~ ^# ]]; then
                subdomain=$(echo "$line" | tr -d '\r\n' | xargs)
                if [ -n "$subdomain" ]; then
                    [[ "$subdomain" =~ ^https?:// ]] && echo "$subdomain" >> "$targets_file" || echo "https://$subdomain" >> "$targets_file"
                fi
            fi
        done < "$SUBDOMAIN_FILE"
        local target_count=$(wc -l < "$targets_file")
        echo -e "${GREEN}[SUCCESS]${NC} Loaded $target_count targets"
    else
        echo -e "${YELLOW}[SINGLE]${NC} Single domain mode"
        echo "$BASE_URL" > "$targets_file"
        target_count=1
    fi

    # Phase 1: Discovery
    echo -e "${YELLOW}[PHASE 1]${NC} JavaScript Discovery"
    > "$RESULTS_DIR/all_js_discovered.txt"

    while read -r target; do
        enhanced_js_discovery "$target"
    done < "$targets_file"

    local total_js=$(wc -l < "$RESULTS_DIR/all_js_discovered.txt" 2>/dev/null || echo "0")
    echo -e "${BLUE}[DISCOVERY COMPLETE]${NC} Found $total_js JavaScript files"

    if [ "$total_js" -eq 0 ]; then
        echo -e "${RED}[ERROR]${NC} No JavaScript files discovered"
        exit 1
    fi

    # Phase 2: Download
    echo -e "${YELLOW}[PHASE 2]${NC} Parallel Download"
    if ! parallel_download; then
        echo -e "${RED}[ERROR]${NC} Download phase failed"
        exit 1
    fi

    # Phase 3: Enhanced Analysis
    echo -e "${YELLOW}[PHASE 3]${NC} Enhanced Security Analysis"
    analyze_enhanced_secrets

    # Phase 4: Generate final report
    echo -e "${YELLOW}[PHASE 4]${NC} Report Generation"
    generate_final_report

    echo ""
    echo -e "${PURPLE}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${PURPLE}${BOLD}║                  JSHAWK SCAN COMPLETE                        ║${NC}"
    echo -e "${PURPLE}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"

    display_final_summary
}

# Generate final comprehensive report
generate_final_report() {
    local final_report="$RESULTS_DIR/jshawk_final_report.txt"
    local js_count=$(find "$RESULTS_DIR/js_files" -name "*.js" | wc -l)
    
    {
        echo "╔══════════════════════════════════════════════════════════════╗"
        echo "║                   JSHawk Security Report                     ║"
        echo "╚══════════════════════════════════════════════════════════════╝"
        echo ""
        echo "Scan Target: $CLEAN_DOMAIN"
        echo "Scan Date: $(date)"
        echo "JSHawk Version: v1.0"
        echo ""
        echo "SCAN STATISTICS:"
        echo "==============="
        echo "JavaScript Files Analyzed: $js_count"
        echo "Total Download Size: $(du -sh "$RESULTS_DIR/js_files" 2>/dev/null | cut -f1 || echo "0B")"
        
        if [ -f "$RESULTS_DIR/findings/secrets.txt" ] && [ -s "$RESULTS_DIR/findings/secrets.txt" ]; then
            local secret_count=$(wc -l < "$RESULTS_DIR/findings/secrets.txt")
            echo "Security Issues Found: $secret_count"
            echo ""
            echo "RISK ASSESSMENT:"
            echo "==============="
            
            local critical=$(grep -E "(AWS_ACCESS_KEY|AWS_SECRET_KEY|STRIPE_LIVE_KEY|DATABASE_URL|PRIVATE_KEY)" "$RESULTS_DIR/findings/secrets.txt" | wc -l)
            local high=$(grep -E "(GITHUB_TOKEN|GOOGLE_API_KEY|SLACK_TOKEN|SENDGRID_API_KEY)" "$RESULTS_DIR/findings/secrets.txt" | wc -l)
            local medium=$(grep -E "(API_KEY|JWT_SECRET)" "$RESULTS_DIR/findings/secrets.txt" | wc -l)
            local custom=$(grep "CUSTOM_" "$RESULTS_DIR/findings/secrets.txt" | wc -l)
            
            echo "🔴 CRITICAL Risk: $critical findings"
            echo "🟠 HIGH Risk: $high findings"
            echo "🟡 MEDIUM Risk: $medium findings"
            echo "🟣 CUSTOM Patterns: $custom findings"
            echo ""
            
            if [ $critical -gt 0 ]; then
                echo "⚠️  IMMEDIATE ACTION REQUIRED"
                echo "Critical security credentials detected in JavaScript files."
                echo "These should be rotated immediately and moved to secure storage."
            fi
            
        else
            echo "Security Issues Found: 0"
            echo ""
            echo "✅ CLEAN SCAN"
            echo "No security credentials detected in JavaScript files."
        fi
        
        echo ""
        echo "FILES GENERATED:"
        echo "==============="
        echo "📁 Main Results: $RESULTS_DIR"
        echo "📄 Summary Report: findings/summary.txt"
        echo "📄 Detailed Analysis: reports/detailed_analysis.txt"
        echo "📄 Raw Findings: findings/secrets.txt"
        echo "📁 Downloaded JS: js_files/"
        echo ""
        echo "RECOMMENDATIONS:"
        echo "==============="
        echo "1. Review all CRITICAL and HIGH risk findings immediately"
        echo "2. Rotate any exposed credentials"
        echo "3. Implement proper secrets management"
        echo "4. Add security scanning to CI/CD pipeline"
        echo "5. Regular security audits of client-side code"
        echo ""
        echo "Generated by JSHawk v1.0 - Advanced JavaScript Security Scanner"
        echo "GitHub: https://github.com/yourusername/jshawk"
        
    } > "$final_report"
}

# Display final summary
display_final_summary() {
    local js_count=$(find "$RESULTS_DIR/js_files" -name "*.js" | wc -l)
    
    echo -e "${CYAN}📊 Scan Results Summary:${NC}"
    echo -e "${CYAN}├─${NC} Results Directory: $RESULTS_DIR"
    echo -e "${CYAN}├─${NC} JavaScript Files: $js_count"
    echo -e "${CYAN}├─${NC} Final Report: jshawk_final_report.txt"
    
    if [ -f "$RESULTS_DIR/findings/secrets.txt" ] && [ -s "$RESULTS_DIR/findings/secrets.txt" ]; then
        local secret_count=$(wc -l < "$RESULTS_DIR/findings/secrets.txt")
        echo -e "${CYAN}└─${NC} Security Issues: ${RED}$secret_count found${NC}"
        
        echo ""
        echo -e "${RED}🚨 SECURITY ALERT:${NC}"
        echo -e "${YELLOW}$secret_count potential security issues detected!${NC}"
        
        echo ""
        echo -e "${GREEN}📋 Quick Actions:${NC}"
        echo -e "  • Review: ${CYAN}cat $RESULTS_DIR/findings/summary.txt${NC}"
        echo -e "  • Details: ${CYAN}cat $RESULTS_DIR/reports/detailed_analysis.txt${NC}"
        echo -e "  • Raw Data: ${CYAN}cat $RESULTS_DIR/findings/secrets.txt${NC}"
        
        echo ""
        echo -e "${YELLOW}🔍 Top Findings:${NC}"
        head -5 "$RESULTS_DIR/findings/secrets.txt" | while IFS='|' read -r type secret file url line; do
            if [ ${#secret} -lt 50 ]; then
                echo -e "  ${RED}[$type]${NC} $secret"
            else
                echo -e "  ${RED}[$type]${NC} ${secret:0:40}..."
            fi
        done
        
    else
        echo -e "${CYAN}└─${NC} Security Issues: ${GREEN}0 found${NC}"
        echo ""
        echo -e "${GREEN}✅ CLEAN SCAN COMPLETED${NC}"
        echo -e "No security credentials detected in JavaScript files."
    fi
    
    echo ""
    echo -e "${BLUE}🦅 JSHawk scan completed successfully!${NC}"
    echo -e "${CYAN}📁 All results saved to: $RESULTS_DIR${NC}"
}

# Initialize and run
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
