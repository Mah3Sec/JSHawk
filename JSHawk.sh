def analyze_js_file(self, js_url):
        """Analyze a single JavaScript file for secrets"""
        try:
            response = self.session.get(js_url, timeout=self.timeout)
            if response.status_code == 200:
                content = response.text
                secrets = self.extract_secrets(content, js_url)
                endpoints = self.extract_endpoints(content, js_url)
                return secrets, endpoints
        except Exception as e:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Failed to analyze {js_url}: {e}")
        return [], []

    def analyze_source_map(self, map_url):
        """Analyze source map files for secrets"""
        try:
            if '#inline' in map_url:
                # Handle inline source maps
                js_url = map_url.replace('#inline', '')
                js_response = self.session.get(js_url, timeout=self.timeout)
                if js_response.status_code == 200:
                    # Extract inline source map
                    content = js_response.text
                    inline_pattern = r'//# sourceMappingURL=data:application/json;(?:charset=utf-8;)?base64,([A-Za-z0-9+/=]+)'
                    matches = re.findall(inline_pattern, content)
                    if matches:
                        import base64
                        decoded = base64.b64decode(matches[0]).decode('utf-8')
                        return self.parse_source_map_content(decoded, map_url)
            else:
                # External source map
                response = self.session.get(map_url, timeout=self.timeout)
                if response.status_code == 200:
                    return self.parse_source_map_content(response.text, map_url)
        except Exception as e:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Failed to analyze source map {map_url}: {e}")
        return [], []

    def parse_source_map_content(self, content, source_url):
        """Parse source map JSON content for secrets"""
        try:
            import json
            source_map = json.loads(content)
            all_secrets = []
            
            # Check sources content if available
            if 'sourcesContent' in source_map and source_map['sourcesContent']:
                for i, source_content in enumerate(source_map['sourcesContent']):
                    if source_content:
                        source_name = source_map.get('sources', [f'source_{i}'])[i] if i < len(source_map.get('sources', [])) else f'source_{i}'
                        secrets = self.extract_secrets(source_content, f"{source_url}#{source_name}")
                        all_secrets.extend(secrets)
            
            # Check source map metadata for potential secrets
            for key, value in source_map.items():
                if isinstance(value, str) and len(value) > 10:
                    secrets = self.extract_secrets(value, f"{source_url}#metadata")
                    all_secrets.extend(secrets)
                    
            return all_secrets, []
        except:
            return [], []

    def extract_endpoints(self, content,#!/usr/bin/env python3
"""
JavaScript Secrets Hunter - Bug Bounty Tool
Discovers JS files and extracts hardcoded credentials/secrets
"""

import requests
import re
import argparse
import json
import threading
import time
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
from colorama import Fore, Back, Style, init

# Initialize colorama for cross-platform colored output
init(autoreset=True)

class JSSecretsHunter:
    def __init__(self, target_url, threads=10, timeout=10, user_agent=None):
        self.target_url = target_url if target_url.startswith(('http://', 'https://')) else f'https://{target_url}'
        self.domain = urlparse(self.target_url).netloc
        self.threads = threads
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': user_agent or 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.js_files = set()
        self.secrets_found = []
        
        # Comprehensive regex patterns for different types of secrets
        self.patterns = {
            'api_keys': [
                r'["\']?[Aa]pi[_-]?[Kk]ey["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']',
                r'["\']?[Aa]ccess[_-]?[Kk]ey["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']',
                r'["\']?[Ss]ecret[_-]?[Kk]ey["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']',
            ],
            'aws_keys': [
                r'AKIA[0-9A-Z]{16}',
                r'["\']?[Aa]ws[_-]?[Aa]ccess[_-]?[Kk]ey[_-]?[Ii]d["\']?\s*[:=]\s*["\']?(AKIA[0-9A-Z]{16})["\']?',
                r'["\']?[Aa]ws[_-]?[Ss]ecret[_-]?[Aa]ccess[_-]?[Kk]ey["\']?\s*[:=]\s*["\']([A-Za-z0-9/+=]{40})["\']',
            ],
            'database_urls': [
                r'["\']?[Dd]atabase[_-]?[Uu]rl["\']?\s*[:=]\s*["\']([^"\']+://[^"\']+)["\']',
                r'["\']?[Mm]ongo[_-]?[Uu]rl["\']?\s*[:=]\s*["\']([^"\']+://[^"\']+)["\']',
                r'["\']?[Dd]b[_-]?[Uu]rl["\']?\s*[:=]\s*["\']([^"\']+://[^"\']+)["\']',
                r'mysql://[^\s"\']+',
                r'postgres://[^\s"\']+',
                r'mongodb://[^\s"\']+',
            ],
            'jwt_secrets': [
                r'["\']?[Jj]wt[_-]?[Ss]ecret["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']',
                r'["\']?[Jj]wt[_-]?[Kk]ey["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']',
                r'["\']?[Tt]oken[_-]?[Ss]ecret["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']',
            ],
            'passwords': [
                r'["\']?[Pp]assword["\']?\s*[:=]\s*["\']([^"\']{6,})["\']',
                r'["\']?[Pp]ass["\']?\s*[:=]\s*["\']([^"\']{6,})["\']',
                r'["\']?[Pp]wd["\']?\s*[:=]\s*["\']([^"\']{6,})["\']',
            ],
            'usernames': [
                r'["\']?[Uu]sername["\']?\s*[:=]\s*["\']([^"\']{3,})["\']',
                r'["\']?[Uu]ser["\']?\s*[:=]\s*["\']([^"\']{3,})["\']',
                r'["\']?[Aa]dmin[_-]?[Uu]ser["\']?\s*[:=]\s*["\']([^"\']{3,})["\']',
            ],
            'github_tokens': [
                r'ghp_[A-Za-z0-9_]{36}',
                r'gho_[A-Za-z0-9_]{36}',
                r'ghu_[A-Za-z0-9_]{36}',
                r'ghs_[A-Za-z0-9_]{36}',
                r'ghr_[A-Za-z0-9_]{36}',
            ],
            'slack_tokens': [
                r'xox[baprs]-[0-9a-zA-Z\-]+',
                r'["\']?[Ss]lack[_-]?[Tt]oken["\']?\s*[:=]\s*["\']?(xox[baprs]-[0-9a-zA-Z\-]+)["\']?',
            ],
            'discord_tokens': [
                r'[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}',
                r'mfa\.[a-z0-9_\-]{84}',
            ],
            'google_api': [
                r'AIza[0-9A-Za-z\\-_]{35}',
                r'["\']?[Gg]oogle[_-]?[Aa]pi[_-]?[Kk]ey["\']?\s*[:=]\s*["\']?(AIza[0-9A-Za-z\\-_]{35})["\']?',
            ],
            'stripe_keys': [
                r'sk_live_[0-9a-zA-Z]{24,}',
                r'pk_live_[0-9a-zA-Z]{24,}',
                r'rk_live_[0-9a-zA-Z]{24,}',
            ],
            'twilio_keys': [
                r'SK[a-z0-9]{32}',
                r'AC[a-z0-9]{32}',
            ],
            'mailgun_keys': [
                r'key-[0-9a-zA-Z]{32}',
            ],
            'sendgrid_keys': [
                r'SG\.[a-zA-Z0-9_\-\.]{66}',
            ],
            'private_keys': [
                r'-----BEGIN PRIVATE KEY-----[A-Za-z0-9+/=\s]+-----END PRIVATE KEY-----',
                r'-----BEGIN RSA PRIVATE KEY-----[A-Za-z0-9+/=\s]+-----END RSA PRIVATE KEY-----',
            ],
            'firebase_urls': [
                r'https://[a-z0-9\-]+\.firebaseio\.com',
                r'["\']?[Ff]irebase[_-]?[Uu]rl["\']?\s*[:=]\s*["\']?(https://[a-z0-9\-]+\.firebaseio\.com)["\']?',
            ],
            'base64_secrets': [
                r'["\']([A-Za-z0-9+/]{40,}={0,2})["\']',  # Potential base64 encoded secrets
            ]
        }

    def print_banner(self):
        banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║                    JavaScript Secrets Hunter                 ║
║                        Bug Bounty Tool                       ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.YELLOW}Target: {self.target_url}
Threads: {self.threads}
Timeout: {self.timeout}s{Style.RESET_ALL}
"""
        print(banner)

    def discover_js_files(self):
        """Discover JavaScript files from various sources"""
        print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Starting JavaScript file discovery...")
        
        # Common JS file paths to check
        common_paths = [
            '/static/js/',
            '/assets/js/',
            '/js/',
            '/build/static/js/',
            '/dist/js/',
            '/public/js/',
            '/scripts/',
            '/app/',
            '/src/',
        ]
        
        # Try to get the main page and extract JS references
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            if response.status_code == 200:
                self.extract_js_from_html(response.text)
        except Exception as e:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Failed to fetch main page: {e}")

        # Check common paths
        self.check_common_paths(common_paths)
        
        # Check for webpack chunks and common patterns
        self.discover_webpack_chunks()
        
        print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} Discovered {len(self.js_files)} JavaScript files")
        return list(self.js_files)

    def extract_js_from_html(self, html_content):
        """Extract JavaScript file references from HTML"""
        js_patterns = [
            r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']',
            r'<script[^>]+src=([^\s>]+\.js[^\s>]*)',
            r'["\']([^"\']*\.js[^"\']*)["\']',
        ]
        
        for pattern in js_patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            for match in matches:
                if match.endswith('.js') or '.js?' in match:
                    full_url = urljoin(self.target_url, match)
                    self.js_files.add(full_url)

    def check_common_paths(self, paths):
        """Check common JavaScript file paths"""
        def check_path(path):
            try:
                url = urljoin(self.target_url, path)
                response = self.session.get(url, timeout=self.timeout)
                if response.status_code == 200:
                    # Look for JS files in directory listing or extract from content
                    self.extract_js_from_html(response.text)
            except:
                pass

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(check_path, paths)

    def discover_webpack_chunks(self):
        """Discover webpack chunks and common build patterns"""
        webpack_patterns = [
            '/static/js/main.{hash}.chunk.js',
            '/static/js/{number}.{hash}.chunk.js',
            '/static/js/runtime-main.{hash}.js',
            '/static/js/app.{hash}.js',
            '/build/static/js/main.{hash}.js',
            '/js/app.{hash}.js',
            '/js/vendor.{hash}.js',
            '/js/main.{hash}.js',
        ]
        
        # Try common hash lengths and numbers
        hashes = ['[a-f0-9]{8}', '[a-f0-9]{20}', '[a-f0-9]{32}']
        numbers = range(0, 10)
        
        for pattern in webpack_patterns:
            for hash_pattern in hashes:
                test_pattern = pattern.replace('{hash}', hash_pattern)
                if '{number}' in test_pattern:
                    for num in numbers:
                        final_pattern = test_pattern.replace('{number}', str(num))
                        self.try_pattern_discovery(final_pattern)
                else:
                    self.try_pattern_discovery(test_pattern)

    def try_pattern_discovery(self, pattern):
        """Try to discover files matching a pattern"""
        # This would typically involve trying common hash values
        # For now, we'll add some common examples
        common_hashes = [
            'a1b2c3d4', '12345678', 'abcdef12', 
            '9a8b7c6d5e4f3g2h1i0j', 'main', 'app'
        ]
        
        for hash_val in common_hashes:
            test_url = pattern.replace('[a-f0-9]{8}', hash_val).replace('[a-f0-9]{20}', hash_val*3).replace('[a-f0-9]{32}', hash_val*4)
            try:
                full_url = urljoin(self.target_url, test_url)
                response = self.session.head(full_url, timeout=self.timeout)
                if response.status_code == 200:
                    self.js_files.add(full_url)
            except:
                continue

    def analyze_js_file(self, js_url):
        """Analyze a single JavaScript file for secrets"""
        try:
            response = self.session.get(js_url, timeout=self.timeout)
            if response.status_code == 200:
                content = response.text
                secrets = self.extract_secrets(content, js_url)
                return secrets
        except Exception as e:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Failed to analyze {js_url}: {e}")
        return []

    def extract_secrets(self, content, source_url):
        """Extract secrets from JavaScript content using regex patterns"""
        found_secrets = []
        
        for category, patterns in self.patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    secret_value = match.group(1) if match.groups() else match.group(0)
                    
                    # Skip common false positives
                    if self.is_false_positive(secret_value, category):
                        continue
                    
                    # Get surrounding context
                    start = max(0, match.start() - 50)
                    end = min(len(content), match.end() + 50)
                    context = content[start:end].replace('\n', ' ').strip()
                    
                    secret_info = {
                        'category': category,
                        'value': secret_value,
                        'pattern': pattern,
                        'source': source_url,
                        'context': context,
                        'line_number': content[:match.start()].count('\n') + 1
                    }
                    
                    found_secrets.append(secret_info)
                    
        return found_secrets

    def is_false_positive(self, value, category):
        """Filter out common false positives"""
        false_positives = {
            'passwords': ['password', 'pass', '123456', 'admin', 'test', 'demo', 'example'],
            'usernames': ['user', 'admin', 'test', 'demo', 'example', 'username'],
            'api_keys': ['your-api-key', 'api-key-here', 'your_api_key', 'xxxx', 'yyyy'],
            'base64_secrets': ['placeholder', 'example', 'test', 'demo']
        }
        
        if category in false_positives:
            value_lower = value.lower()
            for fp in false_positives[category]:
                if fp in value_lower or len(value) < 8:
                    return True
        
        return False

    def run_analysis(self):
        """Main function to run the complete analysis"""
        self.print_banner()
        
        # Step 1: Discover JS files
        js_files = self.discover_js_files()
        
        if not js_files:
            print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} No JavaScript files found to analyze")
            return
            
        print(f"\n{Fore.BLUE}[INFO]{Style.RESET_ALL} Analyzing {len(js_files)} JavaScript files for secrets...")
        
        # Step 2: Analyze files for secrets
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_url = {executor.submit(self.analyze_js_file, url): url for url in js_files}
            
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    secrets = future.result()
                    if secrets:
                        self.secrets_found.extend(secrets)
                        print(f"{Fore.GREEN}[FOUND]{Style.RESET_ALL} {len(secrets)} secrets in {url}")
                    else:
                        print(f"{Fore.CYAN}[CLEAN]{Style.RESET_ALL} No secrets found in {url}")
                except Exception as e:
                    print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Error analyzing {url}: {e}")

        # Display results
        self.display_results()

    def display_results(self):
        """Display the analysis results"""
        print(f"\n{Fore.MAGENTA}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}                           ANALYSIS RESULTS{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}{'='*80}{Style.RESET_ALL}\n")
        
        if not self.secrets_found:
            print(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} No secrets found in the analyzed files.")
            return
            
        # Group secrets by category
        by_category = {}
        for secret in self.secrets_found:
            category = secret['category']
            if category not in by_category:
                by_category[category] = []
            by_category[category].append(secret)
            
        print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} Found {len(self.secrets_found)} potential secrets across {len(by_category)} categories\n")
        
        for category, secrets in by_category.items():
            print(f"{Fore.CYAN}┌─ {category.upper()} ({len(secrets)} found){Style.RESET_ALL}")
            for i, secret in enumerate(secrets, 1):
                print(f"{Fore.CYAN}├─{Style.RESET_ALL} {i}. {Fore.RED}{secret['value']}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}│   Source:{Style.RESET_ALL} {secret['source']}")
                print(f"{Fore.CYAN}│   Line:{Style.RESET_ALL} {secret['line_number']}")
                print(f"{Fore.CYAN}│   Context:{Style.RESET_ALL} ...{secret['context']}...")
                if i < len(secrets):
                    print(f"{Fore.CYAN}│{Style.RESET_ALL}")
            print(f"{Fore.CYAN}└─{Style.RESET_ALL}\n")

    def save_results(self, output_file):
        """Save results to JSON file"""
        results = {
            'target': self.target_url,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'statistics': {
                'js_files_found': len(self.js_files),
                'source_maps_found': len(self.source_maps),
                'secrets_found': len(self.secrets_found),
                'endpoints_found': len(self.endpoints_found)
            },
            'secrets': self.secrets_found,
            'endpoints': self.endpoints_found,
            'js_files': list(self.js_files),
            'source_maps': list(self.source_maps)
        }
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} Results saved to {output_file}")

def main():
    parser = argparse.ArgumentParser(description='JavaScript Secrets Hunter - Bug Bounty Tool')
    parser.add_argument('url', help='Target URL to analyze')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('-o', '--output', help='Output JSON file for results')
    parser.add_argument('--user-agent', help='Custom User-Agent string')
    
    args = parser.parse_args()
    
    hunter = JSSecretsHunter(
        target_url=args.url,
        threads=args.threads,
        timeout=args.timeout,
        user_agent=args.user_agent
    )
    
    try:
        hunter.run_analysis()
        
        if args.output:
            hunter.save_results(args.output)
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[INFO]{Style.RESET_ALL} Analysis interrupted by user")
    except Exception as e:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Unexpected error: {e}")

if __name__ == "__main__":
    main()
