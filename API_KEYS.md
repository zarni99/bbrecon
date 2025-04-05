# API Keys Configuration Guide

## Overview

BBRECON supports both free and premium sources for reconnaissance. Free sources work without configuration, but to access premium sources, you need to provide valid API keys. This guide explains how to set up and manage your API keys effectively.

## How API Keys Work

1. **Free vs. Premium Sources**:
   - Free sources (14 available) work without any API keys
   - Premium sources (32+ available) require valid API keys

2. **API Key Management**:
   - You only need to add the API keys you actually have
   - The system will automatically use available free sources and premium sources with valid keys
   - Missing API keys simply mean those premium sources will be skipped

3. **API Key File Location**:
   - Default location: `api_keys.yaml` in the same directory as the executable
   - Alternative location: `~/.config/bbrecon/api_keys.yaml`

## Setting Up API Keys

1. Copy the template file:
   ```bash
   cp api_keys.yaml.template api_keys.yaml
   ```

2. Edit the file and add your actual API keys:
   ```bash
   vim api_keys.yaml
   ```

3. Important rules:
   - Only add keys you actually have
   - Delete lines or leave empty "" for services you don't use
   - Keep the exact key names as shown in the template
   - Never use placeholders like "YOUR_API_KEY" (they get ignored)

## API Key Format

The API keys file uses a simple YAML format with keys grouped by category:

```yaml
# PRIMARY SOURCES
virustotal_api_key: "your_actual_key_here"
shodan_api_key: "your_actual_key_here"

# Leave empty or delete lines for services you don't use
securitytrails_api_key: ""
```

## Most Valuable API Keys

These API keys provide the most valuable results for subdomain enumeration:

1. **VirusTotal** - https://virustotal.com/
   - Free tier available (limited requests)
   - Provides extensive subdomain data

2. **Shodan** - https://shodan.io/
   - Free tier available (limited results)
   - Excellent for host discovery

3. **SecurityTrails** - https://securitytrails.com/
   - Free tier available (limited requests)
   - Great for historical DNS data

4. **Censys** - https://censys.io/
   - Free tier available
   - Requires both API ID and secret

5. **GitHub** - https://github.com/settings/tokens
   - Create a personal access token
   - Used for code search and additional domain discovery

## Checking API Key Status

Run the tool with `-S` and `-debug` flags to see detailed API key status:

```bash
./bbrecon -t example.com -S -debug
```

You'll see output like:
```
Loading API keys from: api_keys.yaml
API Keys: Found 5 keys (virustotal, shodan, github, ...)
```

## Troubleshooting

If your API keys aren't recognized:

1. **Formatting Issues**:
   - Make sure there are no extra spaces in the key values
   - Verify that the key names match exactly what's in the template

2. **Placeholders**:
   - The system ignores keys containing "YOUR_" or "XXXX"
   - Replace placeholders with actual keys or leave empty

3. **File Location**:
   - Verify that the API keys file is in the correct location
   - Try using the absolute path with the `-c` flag

4. **API Key Validation**:
   - Check if your API keys are actually valid
   - Verify that they haven't expired or been rate-limited

## Premium Sources by Category

### Subdomain Sources
- SecurityTrails, Censys, VirusTotal, Shodan, Certspotter, Spyse, FullHunt, BinaryEdge, Chaos, Netlas, LeakIX, etc.

### DNS Intelligence
- DNSDB, DNSDumpster, Robtex, DNSRepo, ViewDNS, etc.

### Web Intelligence
- URLScan, BuiltWith, WhatCMS, etc.

### Threat Intelligence
- AlienVault, ThreatBook, ThreatMiner, HybridAnalysis, Maltiverse, etc.

## Best Practices

1. **Start Small**: Begin with a few key services like VirusTotal and Shodan
2. **Manage Rate Limits**: Be aware of your API usage to avoid hitting limits
3. **Rotate Keys**: For services with limited free tiers, consider rotating keys
4. **Secure Storage**: Keep your API keys secure and don't share your configuration file
5. **Regular Updates**: Check for expired keys and update them as needed

## Example API Keys Configuration

```yaml
# PRIMARY SOURCES
virustotal_api_key: "ab3d5f7890c12345678901234567890abcdef12345678901234567890"
shodan_api_key: "a1B2c3D4e5F6g7H8i9J0"
securitytrails_api_key: "abcdef1234567890abcdef1234567890"
censys_api_id: "12345678-abcd-1234-abcd-1234567890ab"
censys_api_secret: "ABcdEF1234567890aBcDeF1234567890"
github_api_key: "ghp_abcdefghijklmnopqrstuvwxyz1234567890"

# Only add the keys you actually have, leave others empty or delete
binaryedge_api_key: ""
fullhunt_api_key: ""
``` 