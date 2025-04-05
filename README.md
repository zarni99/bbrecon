# BBRECON - Bug Bounty Reconnaissance Tool

<p align="center">
  <strong>A comprehensive reconnaissance framework for bug bounty hunters and penetration testers.</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#usage">Usage</a> •
  <a href="#modules">Modules</a> •
  <a href="#api-keys">API Keys</a> •
  <a href="#examples">Examples</a> •
  <a href="#screenshots">Screenshots</a> •
  <a href="#license">License</a>
</p>

Created by: Zarni (Neo)

---

## Features

BBRECON automates the reconnaissance phase of bug bounty hunting and penetration testing by providing a modular and comprehensive toolkit:

- **Subdomain Enumeration** - Discover subdomains using multiple sources and techniques
- **DNS Enumeration** - Analyze DNS records and identify security issues
- **HTTP Probing** - Identify active web services and gather information
- **Directory Bruteforcing** - Discover hidden directories and files
- **JavaScript Analysis** - Extract endpoints, secrets, and sensitive information
- **Subdomain Takeover Verification** - Detect and verify subdomain takeover vulnerabilities
- **Cloud Asset Discovery** - Identify cloud resources (AWS, Azure, GCP) associated with a target domain

### Key Highlights

- **Modular Architecture** - Run individual modules or chain them together
- **Multiple Sources** - Utilize numerous free and premium data sources
- **Comprehensive Output** - Get detailed, well-structured results
- **API Key Management** - Securely use your own API keys for enhanced results
- **Performance Optimized** - Concurrent operations with rate limiting
- **User-Friendly Interface** - Interactive target selection with prioritization
- **Flexible Output Options** - Save results in various formats and locations
- **Intelligent Workflow** - Smart time estimation and sampling for large targets
- **Accurate Progress Tracking** - Enhanced progress bars show accurate completion status
- **Actionable Security Findings** - Detailed remediation steps for issues like subdomain takeover

## Installation

### Requirements

- Go 1.18 or higher
- Git

### From Source

1. Clone the repository:
```bash
git clone https://github.com/zarni99/bbrecon.git
cd bbrecon
```

2. Build the tool:
```bash
go build -o bbrecon ./cmd
```

3. Make it executable (optional, for easier access):
```bash
chmod +x bbrecon
sudo mv bbrecon /usr/local/bin/
```

## Quick Start

Run a basic scan with subdomain enumeration and HTTP probing:

```bash
./bbrecon -t example.com
```

Run all available modules for comprehensive reconnaissance:

```bash
./bbrecon -t example.com -A
```

Use a custom target file with multiple domains:

```bash
./bbrecon -C targets.txt -S -H
```

## Usage

```
./bbrecon -t example.com [OPTIONS]               # Single domain
./bbrecon -t domain1.com,domain2.com [OPTIONS]   # Multiple domains (comma-separated)
./bbrecon -C targets.txt -S -H                   # Load domains from file (with -S and/or -H)
```

### Essential Flags

```
-t <domain>      Target domain (required unless -C is used)
-C <file>        Custom target file with domains (one per line)
-o <file>        Output file path and location
-h               Show help information
```

### Module Flags

```
-S               Enable Subdomain Enumeration
-N               Enable DNS Enumeration (single domain only)
-H               Enable HTTP Probing
-D               Enable Directory Bruteforcing (single domain only)
-J               Enable JavaScript Analysis (single domain only)
-A               Enable ALL modules in sequence (single domain only)
```

### Flag Restrictions

```
-S and -H        Cannot be used together (use -A for combined functionality)
-C               Must be used with -S and/or -H only (not with -D, -J, -N, or -A)
```

### Subdomain Enumeration Options

```
-s               Comma-separated list of sources to use
-es              Comma-separated list of sources to exclude
-recursive       Use sources that support recursive enumeration
-all             Use all available sources
-stats           Show source statistics
```

### Performance Options

```
-th <number>     Number of concurrent threads (default: 10)
-to <number>     Timeout in seconds (default: 30)
```

### Output Options

```
-json            Output in JSON format
-silent          Suppress banner and progress information
-v               Verbose output
-debug           Debug output with technical details
```

## Modules

### Subdomain Enumeration (-S)

Discovers subdomains using multiple sources:
- Free sources: crt.sh, HackerTarget, AlienVault OTX, URLScan, and more
- Premium sources (with API keys): SecurityTrails, VirusTotal, Shodan, and more

```bash
./bbrecon -t example.com -S
```

### DNS Enumeration (-N)

Analyzes DNS records and identifies security issues:
- Record types: A, AAAA, CNAME, MX, NS, TXT, SOA, SRV, CAA, etc.
- Security checks: SPF/DMARC issues, subdomain takeover verification, etc.
- Provides specific remediation steps for detected issues

```bash
./bbrecon -t example.com -N
```

### HTTP Probing (-H)

Identifies active web services and gathers information:
- Status codes, titles, server headers, response sizes
- Protocol detection (HTTP/HTTPS)
- Technology fingerprinting (detects web frameworks, libraries, CMS, etc.)
- Version detection for common technologies
- Security header analysis

```bash
./bbrecon -t example.com -H
```

### Directory Bruteforcing (-D)

Discovers hidden directories and files:
- Custom wordlist support
- Interactive target selection

```bash
./bbrecon -t example.com -D -w wordlists/directories.txt
```

### JavaScript Analysis (-J)

Extracts endpoints, secrets, and sensitive information:
- API endpoints discovery
- Secrets/token detection
- DOM-based XSS vulnerability identification

```bash
./bbrecon -t example.com -J
```

### Cloud Asset Discovery

Discovers cloud resources associated with a target domain:
- AWS resources: S3 buckets, Lambda functions, and more
- Azure resources: Blob storage, App Services, and more
- GCP resources: Cloud Storage, Cloud Functions, and more
- Detects vulnerable cloud configurations

```bash
# Use the general cloud discovery flag (enables all providers)
./bbrecon -t example.com -l

# Alternative syntax for cloud discovery
./bbrecon -t example.com -l

# Specific cloud provider discovery
./bbrecon -t example.com -aws     # AWS only
./bbrecon -t example.com -az      # Azure only
./bbrecon -t example.com -gcp     # GCP only

# Specify AWS region
./bbrecon -t example.com -aws -aws-region us-west-2
```

For more detailed information about this module, refer to the [MANUAL.md](MANUAL.md) file.

## API Keys

BBRECON supports various premium sources that require API keys. To use these sources:

1. Copy the template file:
```bash
cp api_keys.yaml.template api_keys.yaml
```

2. Add your API keys to `api_keys.yaml`:
```yaml
# Simple key-value format
virustotal_api_key: "your_key_here"
shodan_api_key: "your_key_here"
securitytrails_api_key: "your_key_here"
```

The file `api_keys.yaml` is automatically ignored by git for security.

## Examples

### Basic Scan

```bash
./bbrecon -t example.com
```

### Full Reconnaissance

```bash
./bbrecon -t example.com -A
```

### Subdomain Enumeration with Specific Sources

```bash
./bbrecon -t example.com -S -s crtsh,hackertarget,urlscan
```

### Multiple Domains with Output File

```bash
./bbrecon -t example.com,example.org -S -H -o results.txt
```

### Custom Target File with Subdomain Enumeration

```bash
./bbrecon -C targets.txt -S
```

### Directory Bruteforcing with Custom Wordlist

```bash
./bbrecon -t example.com -D -w /path/to/wordlist.txt
```

### JavaScript Analysis in Silent Mode

```bash
./bbrecon -t example.com -J -silent
```

### Subdomain Takeover Detection

```bash
./bbrecon -t example.com -N
```

Performs DNS enumeration with advanced subdomain takeover verification:
- Detects potential subdomain takeover vulnerabilities
- Actively verifies takeover possibility with HTTP checks
- Provides detailed remediation steps
- Covers 25+ vulnerable service providers

### Cloud Asset Discovery

```bash
# Use the general cloud discovery flag (enables all providers)
./bbrecon -t example.com -l

# Alternative syntax for cloud discovery
./bbrecon -t example.com -l

# Specific cloud provider discovery
./bbrecon -t example.com -aws     # AWS only
./bbrecon -t example.com -az      # Azure only
./bbrecon -t example.com -gcp     # GCP only

# Specify AWS region
./bbrecon -t example.com -aws -aws-region us-west-2
```

## Advanced Usage

For more detailed information on using BBRECON, refer to the [MANUAL.md](MANUAL.md) file.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

Ensure you have explicit permission to test any target domains. The author is not responsible for any misuse or damage caused by this tool. 