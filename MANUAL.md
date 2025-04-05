# Bug Bounty Recon Tool Manual

Created by: Zarni aka NEO

## Overview
The Bug Bounty Recon Tool is a comprehensive reconnaissance framework designed for bug bounty hunters and security researchers. It automates various reconnaissance tasks and integrates multiple data sources to provide thorough target analysis, with a focus on subdomain enumeration and web application discovery.

## Command Line Flags

### Essential Flags
```bash
-t <domain>      Target domain (required unless -C is used)
-c <file>        Configuration file path (optional, default: uses built-in config)
-o <file>        Output file path (all results will be saved in this directory)
                 If not specified, results are saved to './results/' directory
-h               Show help information
```
- **Target Domain (-t)**: Specify the domain you want to target for reconnaissance. This is required unless using the -C flag.
  - When used alone, it auto-enables subdomain enumeration with default sources (14 free and 1 premium)
  - All modules work with this specified target domain
- **Config File (-c)**: Optionally provide a custom configuration file. If not specified, the tool uses a built-in configuration.
- **Output File (-o)**: Define the path for the output file. All results (including subdomain, HTTP probe, directory brute-forcing results) will be saved in the directory specified by this path. If not specified, results are saved to the './results/' directory.
- **Help (-h)**: Display help information about the tool's usage and options.

### Module Flags
```bash
-S               Enable Subdomain Enumeration module (finds subdomains using various sources)
-N               Enable DNS Enumeration module (discovers DNS records and security issues)
-H               Enable HTTP Probing module (detects live web applications)
-D               Enable Directory Bruteforcing module (discovers hidden paths)
-J               Enable JavaScript Analysis module (extracts endpoints and secrets)
-A               Enable SAGA Mode (comprehensive scan in sequential workflow)
-X               Enable Exposure Detection module (detects exposed sensitive information)
-l               Enable Cloud Asset Discovery module (discovers related cloud resources)

NOTE: If only -t is specified, subdomain enumeration and HTTP probing
      will be enabled automatically.
      A built-in wordlist will be used for subdomain enumeration.

IMPORTANT: The -X (Exposure Detection) and -l (Cloud Asset Discovery) 
           modules must be used standalone and cannot be combined with
           other module flags.
```
- **Subdomain Enumeration (-S)**: Activates the module to discover subdomains using multiple sources.
  - When used alone: Uses API-based sources (default: 14 free and 1 premium)
  - When used with `-w`: Enables bruteforce-only mode, disables API sources
  - When used with `-all`: Uses all available sources (14 free and 32 premium)
  - When used with `-s`: Uses only the specified sources
- **DNS Enumeration (-N)**: Discovers and analyzes DNS records and security issues for discovered subdomains.
- **HTTP Probing (-H)**: Checks for live web applications by probing HTTP/HTTPS services.
  - When used alone: Performs enhanced HTTP probe with detailed output (SSL info, security headers, etc.)
  - When used after `-S`: Probes discovered subdomains with basic information
- **Directory Bruteforcing (-D)**: Discovers hidden directories and files
  - Requires `-w` flag unless `-A` is used
  - When used with `-S` and `-H`: Bruteforces directories on live domains found by HTTP probing
  - When used alone: Takes target from `-t` flag directly
- **JavaScript Analysis (-J)**: Analyzes JavaScript files for endpoints, secrets, and sensitive information. The tool now includes a target selection process for JavaScript analysis, allowing users to select specific targets or analyze all available targets. The findings are displayed with the number of endpoints/secrets found.
- **All Modules (-A)**: Runs all available modules in a sequential workflow (subdomain → DNS → HTTP → directories → JavaScript). This enables saga mode where each module uses the results from the previous module.
  - Must be used standalone with only `-t` (and optionally `-o`)
  - Cannot be combined with other module flags (`-S`, `-H`, `-D`, `-J`, `-N`, `-X`)
  - Shows "Saga mode enabled" message
- **Exposure Detection (-X)**: Detects exposed sensitive information and configuration files
  - Features:
    - API keys and secrets detection
    - Sensitive file discovery
    - JavaScript analysis for secrets
    - Pattern-based detection
    - Severity classification
    - Proof of concept generation
  - Detection Categories:
    1. Cloud Service Credentials:
       - AWS keys and secrets
       - Google Cloud Platform service accounts
       - Azure keys
       - DigitalOcean tokens
       - Firebase credentials
       - Cloudflare API keys
    2. Development Platform Tokens:
       - GitHub tokens
       - GitLab personal access tokens
       - NPM tokens
       - Heroku API keys
    3. Payment Service Keys:
       - Stripe API keys
       - Square API keys
       - PayPal access tokens
    4. Communication Service Tokens:
       - Slack tokens and webhooks
       - Discord webhooks
       - Twilio keys
       - SendGrid keys
       - Mailgun keys
       - Mailchimp API keys
    5. Cryptographic Materials:
       - SSH public/private keys
       - PGP private keys
       - Various certificate files
    6. Sensitive Files:
       - Environment files (.env variants)
       - Configuration files (multiple formats)
       - Backup files
       - Log files
       - Database files
       - Docker configuration
       - Kubernetes configuration
  - Special Behaviors:
    - When used standalone: Performs comprehensive exposure detection
    - When used with other modules: Integrates with existing workflow
    - Automatically checks common sensitive file paths
    - Analyzes JavaScript files for embedded secrets
    - Provides proof of concept commands for findings
  - Output: Detailed findings with severity levels and proof of concept
  - Results saved to: `<output-dir>/<target>_EXP_YYMM.txt`
- **Cloud Asset Discovery (-l)**: Discovers cloud resources related to the target domain
  - Features:
    - Permutation-based resource discovery
    - Domain-based resource identification
    - Access level detection (public/private/restricted)
    - Vulnerability assessment for discovered resources
    - Multi-cloud provider support
  - Supported Cloud Providers:
    1. AWS (-aws):
       - S3 buckets
       - Lambda functions
       - EC2 instances
    2. Azure (-az):
       - Azure Blob Storage
       - Azure Functions
       - Azure VMs
    3. GCP (-gcp):
       - Google Cloud Storage
       - Google Cloud Functions
       - Google Compute Engine
  - Discovery Methods:
    - Permutation-based discovery using domain patterns
    - Intelligent name generation based on common naming conventions
    - Public accessibility testing of discovered resources
  - Cloud-Specific Flags:
    - `-aws`: Enable AWS asset discovery
    - `-az`: Enable Azure asset discovery
    - `-gcp`: Enable GCP asset discovery
    - `-aws-region`: Specify AWS region for discovery (default: us-east-1)
    - `-sum`: Show only summary of cloud assets
  - Special Behaviors:
    - Using only `-l` enables all cloud providers
    - Using specific provider flags (e.g., `-aws`) enables only that provider
    - **Must be used as a standalone module** - cannot be combined with other module flags
    - Cloud flags can be used together (e.g., `-aws -az`)
    - The tool will show an error message if you try to combine with other modules
    - Concurrent scanning with configurable thread count
    - Domain-specific resource name generation
  - Output: Detailed findings with accessibility and vulnerability information
  - Results saved to: `<output-dir>/<target>_CLOUD_MMDD.txt`

### Custom Targets
```bash
-C  <file>       Custom target file containing domains/URLs to probe
                 (Can be used instead of -t to process multiple targets)
```
- **Custom Target File (-C)**: Provide a file with URLs/domains for probing. This can be used instead of the -t flag to process multiple targets at once.
  - Must be used with `-S` and/or `-H`
  - Cannot be used with `-D`, `-J`, `-N`, `-A`, or `-X`

### Subdomain Enumeration Options
```bash
-s               Comma-separated list of sources to use
-es              Comma-separated list of sources to exclude
-recursive       Use only sources that can handle subdomains recursively
-all             Use all sources for enumeration
-m               Match subdomains using patterns (comma-separated or file)
-f               Filter out subdomains using patterns (comma-separated or file)
-ip              Resolve and include IP addresses in output
-stats           Show statistics for each source used in subdomain enumeration
```
- **Sources (-s)**: Specify which sources to use for subdomain enumeration.
- **Exclude Sources (-es)**: List sources to exclude from the enumeration process.
- **Recursive (-recursive)**: Use sources capable of recursive subdomain enumeration.
- **All Sources (-all)**: Utilize all available sources for enumeration (14 free and 32 premium) instead of default sources.
- **Match Patterns (-m)**: Define patterns to match subdomains (can be a comma-separated list or a file).
- **Filter Patterns (-f)**: Exclude subdomains that match specified patterns (can be a comma-separated list or a file).
- **Include IPs (-ip)**: Resolve and include IP addresses in the output.
- **Show Stats (-stats)**: Display detailed statistics for each source used in subdomain enumeration. Shows the number of subdomains found per source and the percentage contribution of each source to the total. Statistics are also saved to the output file with additional metadata.

### Output Options
```bash
-json            Write output in JSON format (better for parsing)
-silent          Silent mode - suppress banner and progress output
-no-results      Suppress individual result output, show only summary (default: true)
-v               Enable verbose mode (shows detailed progress)
-debug           Enable debug mode (shows technical details)
-no-js-errors    Suppress JavaScript analysis error messages
```
- **JSON Output (-json)**: Save results in JSON format for easier parsing and integration.
- **Silent Mode (-silent)**: Suppress banner and progress output, only show results.
- **No Results (-no-results)**: Suppress individual result output, only show summary (enabled by default).
- **Verbose Mode (-v)**: Display detailed progress information during execution.
- **Debug Mode (-debug)**: Show technical details for debugging purposes.
- **No JS Errors (-no-js-errors)**: Suppress JavaScript analysis error messages to reduce noise.

### Performance Options
```bash
-th <number>     Number of concurrent threads (default: 10)
                 Higher values = faster but may trigger rate limits
-to <number>     Timeout in seconds for requests (default: 30)
                 Increase for slower connections/targets
```
- **Threads (-th)**: Set the number of concurrent threads. Higher values increase speed but may hit rate limits.
- **Timeout (-to)**: Define the timeout for requests in seconds. Increase for slower connections.

### Wordlist Options
```bash
-w  <file>       Path to wordlist file
                 Required for:
                 - Directory bruteforcing (-D) if default wordlist not found
                 - Subdomain enumeration (-S) when not using API sources and default wordlist not found
                 Default wordlists in wordlists/ directory will be used if available
                 In -A (saga) mode, wordlist is optional for directory bruteforcing

                 Special behavior with -S:
                 - When used together with -S, enables bruteforce-only mode (disables API sources)
                 - Message "Subdomain enumeration mode: Bruteforce only" will be displayed
```
- **Wordlist (-w)**: Specify a custom wordlist file for directory bruteforcing and subdomain enumeration. The tool will attempt to use default wordlists from the wordlists/ directory if available. In saga mode (-A), the tool can run directory bruteforcing without a wordlist by using interactive target selection.
  - With `-S`: Enables subdomain bruteforcing only mode (disables API sources)
  - With `-D`: Uses the specified wordlist for directory bruteforcing
  - Without module flags: Sets the wordlist for both subdomain and directory modules if enabled

## Module Details

### Subdomain Enumeration (-S)
- Discovers subdomains using multiple sources and techniques:
  - API Sources: VirusTotal, SecurityTrails, Censys, Certspotter, etc.
  - Certificate Transparency logs (crt.sh, Facebook CT)
  - DNS bruteforce (with wordlist)
  - Recursive enumeration support
  - Additional sources: Anubis, Leakix, Netlas, RapidDNS, ThreatBook, IntelX
- Features:
  - Pattern matching and filtering
  - IP resolution
  - Source tracking
  - Per-source rate limiting
  - Exponential backoff retry mechanism
  - Source-specific timeouts
  - Automatic request window management
  - Source statistics (-stats)
    - Shows number of subdomains found per source
    - Displays percentage contribution of each source
    - Sorted by number of findings in descending order
    - Includes statistics in output file as metadata comments
    - Useful for identifying most valuable sources for specific targets
- Special Behaviors:
  - Default behavior: Uses 14 free and 1 premium sources
  - With `-w`: Uses only bruteforce mode with the specified wordlist (disables API sources)
  - With `-all`: Uses all available sources (46 total)
  - With `-s "source1,source2"`: Uses only specified sources
  - With `-es "source1,source2"`: Uses all sources except the specified ones
- Output: List of discovered subdomains with metadata
- Results saved to: 
  - If `-o <file>` is specified: `<directory-of-file>/<target>_SD_YYMM.txt`
  - Default: `results/<target>_SD_YYMM.txt`

### DNS Enumeration (-N)
- Discovers and analyzes DNS records for domains:
  - Record Types: A, AAAA, CNAME, MX, NS, TXT, SOA, SRV, CAA, PTR, etc.
  - SPF and DMARC record analysis
  - CAA record verification
  - Nameserver configuration checks
  - Enhanced subdomain takeover detection and verification
- Features:
  - Parallel querying of multiple record types
  - Security issue detection with severity classification
  - Custom DNS resolver support
  - Comprehensive output organized by record type
  - Email security configuration analysis
  - Real-time progress tracking with accurate completion status
  - Intelligent domain sampling for large subdomain sets
  - Time estimation for long-running operations
- Special Behaviors:
  - For large subdomain sets (>100 domains), offers intelligent options:
    - Process all domains (with time estimate)
    - Process random sample of 100 domains
    - Skip DNS enumeration
  - Progress indicator shows exact completion percentage (100% when done)
- Security Checks:
  - Missing or misconfigured SPF records (email spoofing risk)
  - Missing or misconfigured DMARC records (email security risk)
  - Missing CAA records (certificate issuance control)
  - Nameserver redundancy issues (DNS resilience)
  - Subdomain takeover vulnerability detection with verification:
    - Covers 25+ vulnerable service providers (AWS, Azure, GitHub, Heroku, etc.)
    - Actively verifies takeover possibility with HTTP requests
    - Provides severity ratings (high/medium)
    - Includes specific remediation steps for each finding
- Display Features:
  - Consolidated progress bar showing scan completion percentage
  - Real-time counter for discovered records and security issues
  - Concise summary of record types organized by frequency
  - Clean output that doesn't flood the terminal with individual findings
- Bug Bounty Value:
  - Identifies subdomain takeover opportunities
  - Reveals email spoofing vulnerabilities
  - Discovers misconfigurations that could lead to phishing
  - Exposes certificate issuance vulnerabilities
  - Maps additional attack surface through DNS relationships
- Output: Structured findings with records and security issues
- Results saved to: `<output-dir>/<target>_DNS_YYMM.txt`

### HTTP Probing (-H)
- Checks for HTTP/HTTPS services
- Features:
  - Protocol detection (HTTP/HTTPS)
  - Status code verification
  - Title extraction
  - Server header analysis
  - Response size tracking
  - Technology fingerprinting (detects web frameworks, libraries, CMS, etc.)
  - Colorful output formatting
  - Deduplication of live subdomains
- Special Behaviors:
  - When used standalone: Performs enhanced HTTP probe with detailed information
    - Displays SSL/TLS information (certificate issuer, expiration date, version)
    - Shows security headers (CSP, X-Frame-Options, HSTS, etc.)
    - Lists web server details and technologies
    - Identifies web technologies with version information when available
    - Categorizes detected technologies (Framework, CMS, JavaScript Library, etc.)
    - Provides a security score based on header implementation
    - Outputs a CURL command for reproducing the request
  - When used after `-S`: Performs basic probing of discovered subdomains
    - Shows status code, content size, and server information
    - Includes detected technologies in concise format
    - More concise output for large numbers of subdomains
- Technology Fingerprinting:
  - Detects over 30 common web technologies including:
    - Content Management Systems (WordPress, Joomla, Drupal)
    - JavaScript Frameworks (React, Angular, Vue.js, Next.js)
    - CSS Frameworks (Bootstrap, Tailwind)
    - Web Servers (Nginx, Apache, IIS)
    - Programming Languages (PHP, ASP.NET)
    - E-commerce Platforms (Shopify, WooCommerce, Magento)
    - Analytics Tools (Google Analytics, Google Tag Manager)
  - Detection methods:
    - HTTP header analysis
    - HTML content pattern matching
    - JavaScript file detection
    - Regular expression-based version extraction
  - Configuration:
    - Technology fingerprinting is enabled by default
    - Can be disabled in the configuration file (detect_technologies: false)
- Output: Active web services with status codes, content sizes, and detected technologies
- Results Format: `URL [STATUS_CODE] [CONTENT_SIZE bytes] [TECHNOLOGIES: Tech1, Tech2]`
- Results saved to: 
  - Regular output: `<output-dir>/<target>_WA_YYMM.txt`
  - Enhanced output (standalone mode): `<output-dir>/<target>_enhanced_http_YYMM.txt`
- Result Statistics:
  - Live: Total number of successful HTTP responses
  - Unique live subdomains: Count of distinct subdomains after deduplication
    - Note: This number is often lower than "Live" count as multiple URLs may point to the same subdomain
    - Example: http://api.example.com and https://api.example.com count as 2 live responses but only 1 unique subdomain

### Directory Bruteforcing (-D)
- Discovers hidden directories and files
- Features:
  - Custom wordlist support
  - Status code filtering
  - Size-based filtering
  - Extension handling
  - Rate limiting protection
  - Interactive target selection with priority-based categorization
  - Pagination, filtering, and sorting in the selection interface
- Special Behaviors:
  - Requires `-w` flag unless `-A` is used
  - When used with `-S` and `-H`: Bruteforces directories on live domains found by HTTP probing
  - When used alone: Takes target from `-t` flag directly
  - Interactive prompts:
    - "Do you want to perform another directory bruteforcing scan?" displayed on same line as input
    - Domain selection interface with improved navigation (removed "select all" option)
- Output: Clean list of discovered URLs, one per line
- Results saved to: `<output-dir>/<target>_DBF_YYMM.txt`

### JavaScript Analysis (-J)
- Analyzes JavaScript files for:
  - API endpoints
  - Secret tokens
  - Sensitive information
  - DOM-based XSS vulnerabilities
  - Dependencies
  - URLs and domains
- Features:
  - Static analysis
  - Pattern matching
  - Entropy-based secret detection
  - JavaScript deobfuscation capability
  - Advanced DOM-based XSS detection
  - Endpoint classification by category
  - Recursive script analysis
  - Context-aware finding display
  - Severity-based findings organization (HIGH, MEDIUM, INFO)
  - Interactive progress indicator
- Output: Structured findings from JS analysis with severity breakdown
- Results saved to: `<output-dir>/<target>_JS_YYMM.txt`

## Interactive Target Selection

The tool provides an interactive target selection interface for directory bruteforcing and JavaScript analysis:

### Target Categorization
- **High Priority**: Targets containing sensitive keywords like admin, portal, login, auth, etc.
- **Medium Priority**: Targets containing keywords like api, dev, test, stage, etc.
- **Low Priority**: All other targets

### Selection Features
- **Pagination**: Browse through targets with next/previous navigation
- **Filtering**: Filter targets by keyword (e.g., 'f:admin') or show only high priority targets
- **Sorting**: Sort targets in ascending or descending order
- **Selection Methods**:
  - Single number: Select a specific target
  - Multiple numbers: Select multiple targets (e.g., 1,3,5)
  - Range: Select a range of targets (e.g., 1-10)
  - 'b': Go back to the previous screen
- **Scan Type Selection**: Choose between directory bruteforcing, JavaScript analysis, or both

## Special Flag Combinations and Behaviors

### `-S` (Subdomain Enumeration)
- `-S` alone: Uses API-based sources (default: 14 free and 1 premium)
- `-S -w wordlist.txt`: Enables bruteforce-only mode, disables API sources
- `-S -all`: Uses all available sources (14 free and 32 premium)
- `-S -s "source1,source2"`: Uses only the specified sources

### `-H` (HTTP Probing)
- `-H` alone: Performs enhanced HTTP probe with detailed output (SSL info, security headers, etc.)
- `-S -H`: Probes discovered subdomains with basic information

### `-D` (Directory Bruteforcing)
- Requires `-w` flag unless `-A` is used
- `-D -w wordlist.txt`: Bruteforces directories on the target specified by `-t`
- `-S -H -D`: Bruteforces directories on live domains found by HTTP probing

### `-A` (All Modules)
- Must be used standalone with only `-t` (and optionally `-o`)
- Cannot be combined with other module flags (`-S`, `-H`, `-D`, `-J`, `-N`, `-X`)
- Runs all modules sequentially with dependencies between modules

### `-C` (Custom Target File)
- Must be used with `-S` and/or `-H`
- Cannot be used with `-D`, `-J`, `-N`, `-A`, or `-X`

### `-X` (Exposure Detection)
- Must be used standalone with only `-t` (and optionally `-o`)
- Cannot be combined with other module flags (`-S`, `-H`, `-D`, `-J`, `-N`, `-A`)
- Runs standalone exposure detection

### Flag Restrictions
```bash
-S and -H        Cannot be used together (use -A or run them separately)
-C               Must be used with -S and/or -H only (not with -D, -J, -N, -A, -X)
-X               Must be used standalone with only -t (and optionally -o)
```

## Available Sources for Subdomain Enumeration

The tool uses the following sources by default (free sources that don't require API keys):
- crtsh - Certificate Transparency logs
- hackertarget - HackerTarget API
- alienvault - AlienVault OTX
- urlscan - Urlscan.io API
- threatminer - ThreatMiner API
- riddler - Riddler.io API
- wayback - WaybackMachine archive
- commoncrawl - CommonCrawl data
- certspotter - CertSpotter API
- anubis - Anubis Database
- threatcrowd - ThreatCrowd API
- rapiddns - RapidDNS API
- sitedossier - SiteDossier API
- hudsonrock - HudsonRock API
- digitorus - Digitorus API

Additional sources available if API keys are configured:
- virustotal - VirusTotal API (requires API key)
- securitytrails - SecurityTrails API (requires API key)
- shodan - Shodan API (requires API key)
- censys - Censys API (requires API key and secret)
- spyse - Spyse API (requires API key)
- fullhunt - FullHunt API (requires API key)
- binaryedge - BinaryEdge API (requires API key)
- threatbook - ThreatBook API (requires API key)
- netlas - Netlas API (requires API key)
- leakix - LeakIX API (requires API key)
- c99 - C99 API (requires API key)
- bevigil - BeVigil API (requires API key)
- intelx - IntelX API (requires API key)
- github - GitHub API (requires API key)
- fofa - FOFA API (requires API key)
- zoomeye - ZoomEye API (requires API key)
- hunter - Hunter.io API (requires API key)
- builtwith - BuiltWith API (requires API key)
- and many more (32 premium sources in total)

## Sequential Workflow (Saga Mode with -A)

The -A flag enables a sequential workflow where each module uses the results from the previous module:

1. Subdomain Enumeration → Discovers subdomains
2. DNS Enumeration → Analyzes DNS records and identifies security issues for discovered subdomains
3. HTTP Probing → Checks only discovered subdomains for live web applications
4. Directory Bruteforcing → Runs only on live web applications
   - In this phase, you can select which targets to scan based on priority:
     - High priority targets: admin interfaces, login portals, etc.
     - Medium priority targets: APIs, dev environments, etc.
     - Low priority targets: other subdomains
   - Options include scanning all targets, high priority only, high and medium, or custom selection
5. JavaScript Analysis → Analyzes JavaScript from live sites

## Examples

### 1. Basic Subdomain Scan
```bash
./bbrecon -t example.com
```
Performs subdomain enumeration and HTTP probing with default settings, saving results to the `results/` directory.

### 2. Advanced Subdomain Enumeration
```bash
./bbrecon -t example.com -S -all -ip -stats -json
```
Full subdomain scan with all sources, IP resolution, source statistics, and JSON output.

### 3. Subdomain Bruteforcing Only
```bash
./bbrecon -t example.com -S -w wordlists/subdomains.txt
```
Performs subdomain enumeration using only wordlist-based bruteforcing (no API sources).

### 4. DNS Analysis
```bash
./bbrecon -t example.com -N
```
Comprehensive DNS analysis with record discovery, security checks for SPF/DMARC/CAA configurations, and subdomain takeover detection - using the new streamlined progress display.

### 5. Enhanced HTTP Probing
```bash
./bbrecon -t example.com -H
```
Performs detailed HTTP probe with SSL info, security headers, and comprehensive output.

### 6. Full Reconnaissance
```bash
./bbrecon -t example.com -A -w wordlists/all.txt -th 20
```
Runs all modules with custom wordlist and increased threads in sequential workflow (saga mode).

### 7. Custom Output Location
```bash
./bbrecon -t example.com -S -o custom/path/output.txt
```
Subdomain enumeration with results saved to `custom/path/example.com_SD_YYMM.txt`.

### 8. JavaScript Analysis Only
```bash
./bbrecon -t example.com -J
```
Only runs JavaScript analysis on the target domain to extract endpoints, API keys, and check for XSS vulnerabilities.

### 9. Custom Target List with HTTP Probing
```bash
./bbrecon -C targets.txt -H
```
Run HTTP probing on a list of targets from a file.

### 10. Directory Bruteforcing with Custom Wordlist
```bash
./bbrecon -t example.com -D -w wordlists/dirs.txt
```
Run directory bruteforcing on the target using a custom wordlist.

### 11. CI/CD Integration
```bash
./bbrecon -t example.com -A -silent -json -o /path/to/ci/output.json
```
Automation-friendly full scan with JSON output, saving all results to the `/path/to/ci/` directory.

### 12. Focus on High-Priority Targets
```bash
./bbrecon -t example.com -A
```
When prompted during target selection, use the 'priority' filter to focus only on high-priority targets.

### 13. DNS Security Analysis
```bash
./bbrecon -t example.com -N -debug
```
Detailed DNS security analysis with verbose output showing all security issues found.

### 14. Limited Source Selection
```bash
./bbrecon -t example.com -S -s "crtsh,hackertarget,certspotter"
```
Subdomain enumeration using only the specified sources.

### 15. Multiple Modules
```bash
./bbrecon -t example.com -S -H -D -w wordlists/directory.txt
```
Run subdomain enumeration, HTTP probing, and directory bruteforcing in sequence.

### 16. Exposure Detection
```bash
./bbrecon -t example.com -X
```
Runs exposure detection to find sensitive information, API keys, and configuration files.

### 17. Source Statistics
```bash
./bbrecon -t example.com -S -stats
```
Runs subdomain enumeration with detailed source statistics, showing which sources contributed the most subdomains. Useful for identifying the most effective sources for a particular target.

### 18. Combined Reconnaissance with Exposure Detection
```bash
./bbrecon -t example.com -A -X
```
Performs full reconnaissance including exposure detection for sensitive information.

## Configuration

### Config File Format (config.yaml)
```yaml
target: example.com
threads: 10
timeout: 30

subdomain_config:
  enabled: true
  enable_bruteforce: false    # Set to true to enable bruteforce
  disable_api_sources: false  # Set to true to disable API sources
  wordlist_path: "wordlists/subdomains.txt"
  sources: []
  excluded_sources: []
  recursive: false
  use_all_sources: false
  match_subdomains: []
  filter_subdomains: []
  collect_sources: false
  resolve_ip: false
  show_stats: false

dns_enum_config:
  enabled: true
  record_types: ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "SRV", "CAA"]
  resolver_ips: []
  check_takeover: true
  all_records: false

http_probe_config:
  enabled: true
  ports: [80, 443, 8080, 8443]
  follow_redirects: true

dir_brute_config:
  enabled: true
  wordlist_path: "wordlists/directories.txt"
  status_codes: [200, 204, 301, 302, 307, 401, 403]

js_analyzer_config:
  enabled: true
  analyze_external: false
  extract_endpoints: true
  detect_secrets: true
  detect_xss: true
  deobfuscate: true
```

## API Configuration

BBRECON supports both free and premium sources for reconnaissance. While free sources work without any configuration, premium sources require valid API keys.

### How API Keys Work

1. **Free vs. Premium Sources**:
   - 14 free sources work without any API keys
   - 32+ premium sources require valid API keys
   - The tool automatically uses free sources plus any premium sources with valid keys

2. **Simple Configuration**:
   - You only need to add API keys you actually have
   - Missing keys simply mean those particular premium sources will be skipped
   - Empty strings or values with "YOUR_" are automatically ignored

### API Keys File

The default locations for the API keys file are:
- `api_keys.yaml` in the same directory as the executable
- `~/.config/bbrecon/api_keys.yaml`

### API Key Format

```yaml
# PRIMARY SOURCES
virustotal_api_key: "your_actual_key_here"    # https://virustotal.com/
shodan_api_key: "your_actual_key_here"        # https://shodan.io/
securitytrails_api_key: ""                    # https://securitytrails.com/
censys_api_id: ""                             # https://censys.io/
censys_api_secret: ""                         # https://censys.io/

# More categories and sources available in the template file
```

### Most Valuable API Keys

These API keys provide the most valuable results:

1. **VirusTotal** - https://virustotal.com/ (free tier available)
2. **Shodan** - https://shodan.io/ (free tier available)
3. **SecurityTrails** - https://securitytrails.com/ (free trial available)
4. **Censys** - https://censys.io/ (free tier available)
5. **GitHub** - https://github.com/settings/tokens (free)

### Quick Start

1. Copy the template file:
   ```bash
   cp api_keys.yaml.template api_keys.yaml
   ```

2. Edit and add only the keys you have:
   ```bash
   vim api_keys.yaml
   ```

3. Run with the -S flag to enable subdomain enumeration:
   ```bash
   ./bbrecon -t example.com -S
   ```

## Cloud Asset Discovery Module

### Overview

The Cloud Asset Discovery module identifies cloud resources (AWS, Azure, GCP) associated with a target domain. This is a standalone module that cannot be used with other modules.

### Command-Line Flags

The cloud asset discovery functionality can be accessed using the following flags:

```bash
# Enable all cloud providers
./bbrecon -t example.com -l

# Specific cloud providers
./bbrecon -t example.com -aws      # AWS only
./bbrecon -t example.com -az       # Azure only 
./bbrecon -t example.com -gcp      # GCP only
./bbrecon -t example.com -aws -az  # AWS and Azure

# Specify AWS region (default is us-east-1)
./bbrecon -t example.com -aws -aws-region us-west-2

# INCORRECT USAGE - will produce an error
./bbrecon -t example.com -l -S     # Cannot combine with other modules
./bbrecon -t example.com -aws -D   # Cannot combine with other modules
```

### Available Flags

| Flag           | Description                                           | Restriction                                |
|----------------|-------------------------------------------------------|-------------------------------------------|
| `-l`           | Enable cloud asset discovery for all providers        | Cannot be used with other module flags     |
| `-aws`         | Enable AWS asset discovery                            | Cannot be used with non-cloud module flags |
| `-az`          | Enable Azure asset discovery                          | Cannot be used with non-cloud module flags |
| `-gcp`         | Enable GCP asset discovery                            | Cannot be used with non-cloud module flags |
| `-aws-region`  | Specify AWS region (default: us-east-1)               | Only used with -aws or -l                  |
| `-sum`         | Show only summary of cloud assets                     | Only used with cloud discovery flags       |

### Important Restrictions

The Cloud Asset Discovery module is designed to operate independently from other modules:

- **Cannot be combined** with other module flags (-S, -H, -D, -J, -N, -X, -A)
- Cloud flags (-l, -aws, -az, -gcp) can be used together in any combination
- The tool will display an error message if you attempt to combine cloud discovery with other modules

### Key Features

- Comprehensive cloud asset discovery across multiple providers
- Identification of public/private access levels
- Detection of vulnerable cloud configurations
- Detailed output with resource metadata
- Summary mode for concise output (-sum flag)

### Supported Cloud Providers

#### AWS
- S3 buckets
- Lambda functions
- CloudFront distributions
- API Gateway endpoints
- EC2 instances
- ELB/ALB load balancers

#### Azure
- Azure Blob Storage
- Azure App Services
- Azure Functions
- Azure CDN endpoints
- Azure SQL databases
- Azure VMs

#### GCP
- Google Cloud Storage
- Google Cloud Functions
- Google App Engine instances
- Google Compute Engine VMs
- Google Kubernetes Engine clusters
- Firebase resources

### Discovery Methodology

1. **Permutation-based discovery**:
   - Generates common resource naming patterns based on the target domain
   - Checks existence of resources across different cloud providers
   - Uses intelligent fuzzing algorithms to find related resources

2. **Access level checks**:
   - Determines if discovered resources are public, private, or restricted
   - Identifies misconfigured resources with unintended public access
   - Detects potential security vulnerabilities

3. **Metadata collection**:
   - Gathers creation date, size, and other metadata when available
   - Collects region and service information
   - Maps relationships between discovered resources

### Output Details

Results include:
- Provider: AWS, Azure, or GCP
- Resource Type: S3 bucket, Azure Blob, etc.
- Resource Name
- Region
- Access Level (public/private)
- URL
- Discovery Method
- Additional Metadata
- Vulnerability Status and Description (if applicable)

### Example Output

```
AWS Assets Discovered: 22
=======================

1. example-test (s3_bucket)
   URL: https://example-test.s3.amazonaws.com
   Region: us-east-1
   Access Level: private
   Discovery Method: permutation
   Additional Info:
     web_url: http://example-test.s3-website-us-east-1.amazonaws.com

2. example-dev (s3_bucket)
   URL: https://example-dev.s3.amazonaws.com
   Region: us-east-1
   Access Level: public
   Discovery Method: permutation
   Vulnerability: S3 bucket is publicly accessible and may contain sensitive data
   Additional Info:
     web_url: http://example-dev.s3-website-us-east-1.amazonaws.com
```

### Programmatic Usage

The cloud asset discovery module can be used directly in Go code:

```go
import (
    "context"
    "fmt"
    
    "github.com/zarni99/bbrecon/pkg/cloudassets"
)

// Create a new cloud asset discovery scanner
cloudScanner, err := cloudassets.NewCloudAssetDiscovery(
    "example.com",     // domain
    "results",         // outputDir
    "us-east-1",       // awsRegion
    true,              // enableAWS
    true,              // enableAzure
    true,              // enableGCP
    10,                // concurrency
    30,                // timeout in seconds
    true,              // debug
)

if err != nil {
    fmt.Printf("Error: %v\n", err)
    return
}

// Run the scan
findings, err := cloudScanner.ScanAll(context.Background())
if err != nil {
    fmt.Printf("Error: %v\n", err)
    return
}

// Process findings
for _, finding := range findings {
    fmt.Printf("Provider: %s, Type: %s, Name: %s\n", 
        finding.Provider, finding.Type, finding.Name)
}
```

### Common Use Cases

1. **Security Assessments**: Discover cloud assets that might be forgotten or improperly secured
2. **Attack Surface Mapping**: Map the cloud footprint of an organization
3. **Vulnerability Detection**: Identify publicly accessible cloud storage that may contain sensitive data
4. **Resource Inventory**: Create a comprehensive inventory of cloud resources across multiple providers
5. **Shadow IT Discovery**: Identify unauthorized or undocumented cloud resources