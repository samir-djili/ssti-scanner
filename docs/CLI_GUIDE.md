# SSTI Scanner CLI Documentation

## Overview

The SSTI Scanner provides a comprehensive command-line interface for detecting Server-Side Template Injection vulnerabilities across multiple template engines. The CLI is designed with modularity and ease of use in mind, offering both simple and advanced usage patterns.

## Installation

```bash
# Install from source
git clone https://github.com/samir-djili/ssti-scanner.git
cd ssti-scanner
pip install -e .[dev]

# Or install from PyPI (when available)
pip install ssti-scanner
```

## Basic Usage

```bash
# Scan a single URL
ssti-scanner scan --url https://example.com/search?q=test

# Scan multiple URLs from file
ssti-scanner scan --file urls.txt

# Quick scan with basic payloads
ssti-scanner scan --url https://example.com --intensity quick

# Comprehensive scan with all features
ssti-scanner scan --url https://example.com --intensity aggressive --crawl-depth 5 --follow-redirects
```

## Command Structure

The SSTI Scanner uses a subcommand-based CLI structure:

```
ssti-scanner <subcommand> [options]
```

### Available Subcommands

- **`scan`** - Main scanning functionality
- **`crawl`** - Web application enumeration and discovery
- **`analyze`** - Form and endpoint analysis
- **`payloads`** - Payload management and generation
- **`report`** - Report generation and conversion
- **`config`** - Configuration management

---

## `scan` - Main Scanning Command

The primary command for detecting SSTI vulnerabilities.

### Syntax
```bash
ssti-scanner scan [options]
```

### Target Specification Options

| Option | Description | Example |
|--------|-------------|---------|
| `-u, --url URL` | Single target URL | `--url https://example.com/search?q=test` |
| `-f, --file FILE` | File containing target URLs | `--file urls.txt` |
| `--burp-file FILE` | Burp Suite proxy history | `--burp-file burp_history.xml` |
| `--zap-file FILE` | OWASP ZAP export file | `--zap-file zap_export.json` |

### Scanning Options

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--intensity LEVEL` | Scan intensity level | `normal` | `--intensity aggressive` |
| `--engines ENGINES` | Target specific engines | All 9 engines | `--engines jinja2,twig,freemarker,velocity,smarty,thymeleaf,handlebars,django,erb` |
| `--crawl-depth DEPTH` | Maximum crawling depth | `3` | `--crawl-depth 5` |
| `--max-pages NUM` | Maximum pages to crawl | `1000` | `--max-pages 500` |
| `--follow-redirects` | Follow HTTP redirects | False | `--follow-redirects` |
| `--blind` | Include blind injection tests | False | `--blind` |
| `--threads NUM` | Number of concurrent threads | `10` | `--threads 20` |
| `--timeout SECONDS` | Request timeout | `30` | `--timeout 60` |
| `--delay SECONDS` | Delay between requests | `0.5` | `--delay 1.0` |

### Authentication Options

| Option | Description | Example |
|--------|-------------|---------|
| `--auth-type TYPE` | Authentication type | `--auth-type bearer` |
| `--username USER` | Username for basic auth | `--username admin` |
| `--password PASS` | Password for basic auth | `--password secret` |
| `--token TOKEN` | Bearer token | `--token eyJ0eXAi...` |
| `--headers HEADERS` | Custom headers (JSON) | `--headers '{"X-API-Key":"123"}'` |
| `--cookies COOKIES` | Session cookies | `--cookies 'session=abc123'` |

### Proxy Options

| Option | Description | Example |
|--------|-------------|---------|
| `--proxy URL` | HTTP/HTTPS proxy | `--proxy http://127.0.0.1:8080` |
| `--proxy-auth AUTH` | Proxy authentication | `--proxy-auth user:pass` |

### Output Options

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `-o, --output FILE` | Output file path | `stdout` | `--output results.json` |
| `--format FORMAT` | Output format | `console` | `--format json` |
| `--no-colors` | Disable colored output | False | `--no-colors` |
| `-v, --verbose` | Verbose output | False | `--verbose` |
| `--debug` | Debug logging | False | `--debug` |

### Examples

#### Basic Scanning
```bash
# Simple URL scan
ssti-scanner scan --url https://testphp.vulnweb.com/search.php?test=query

# Scan with custom intensity
ssti-scanner scan --url https://example.com --intensity aggressive

# Target specific template engines
ssti-scanner scan --url https://example.com --engines jinja2,twig
```

#### File-based Scanning
```bash
# Scan URLs from text file
ssti-scanner scan --file target_urls.txt

# Scan with custom options
ssti-scanner scan --file urls.txt --threads 20 --delay 1.0 --output results.json
```

#### Advanced Scanning
```bash
# Comprehensive scan with crawling
ssti-scanner scan --url https://example.com \
  --intensity aggressive \
  --crawl-depth 5 \
  --follow-redirects \
  --blind \
  --threads 15 \
  --output comprehensive_results.json

# Authenticated scanning
ssti-scanner scan --url https://app.example.com \
  --auth-type bearer \
  --token "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..." \
  --headers '{"X-Requested-With":"XMLHttpRequest"}' \
  --format json
```

---

## `crawl` - Web Application Discovery

Discover and enumerate web application structure without active testing.

### Syntax
```bash
ssti-scanner crawl [options]
```

### Options

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `-u, --url URL` | Target URL to crawl | Required | `--url https://example.com` |
| `--depth DEPTH` | Maximum crawling depth | `3` | `--depth 5` |
| `--max-pages NUM` | Maximum pages to discover | `1000` | `--max-pages 500` |
| `--include-js` | Analyze JavaScript files | False | `--include-js` |
| `--respect-robots` | Respect robots.txt | True | `--no-respect-robots` |
| `--output FILE` | Save crawl results | `stdout` | `--output crawl_results.json` |

### Examples
```bash
# Basic crawling
ssti-scanner crawl --url https://example.com

# Deep crawling with JavaScript analysis
ssti-scanner crawl --url https://spa.example.com --depth 5 --include-js --output crawl_data.json
```

---

## `analyze` - Form and Endpoint Analysis

Analyze discovered forms and endpoints for injection opportunities.

### Syntax
```bash
ssti-scanner analyze [options]
```

### Options

| Option | Description | Example |
|--------|-------------|---------|
| `--crawl-file FILE` | Use previous crawl results | `--crawl-file crawl_data.json` |
| `--forms-only` | Analyze forms only | `--forms-only` |
| `--redirect-tracking` | Enable redirect tracking | `--redirect-tracking` |
| `--output FILE` | Save analysis results | `--output analysis.json` |

---

## `payloads` - Payload Management

Manage and generate payloads for testing.

### Syntax
```bash
ssti-scanner payloads <action> [options]
```

### Actions

#### `list` - List Available Payloads
```bash
# List all payloads
ssti-scanner payloads list

# List payloads for specific engine
ssti-scanner payloads list --engine jinja2

# List by vulnerability type
ssti-scanner payloads list --type code_execution
```

#### `generate` - Generate Custom Payloads
```bash
# Generate context-specific payloads
ssti-scanner payloads generate --context html --engine jinja2

# Generate evasion payloads
ssti-scanner payloads generate --evasion --payload "{{7*7}}"
```

#### `test` - Test Individual Payloads
```bash
# Test single payload
ssti-scanner payloads test --url https://example.com --payload "{{7*7}}"

# Test payload list
ssti-scanner payloads test --url https://example.com --file custom_payloads.txt
```

---

## `report` - Report Management

Generate and convert scan reports between different formats.

### Syntax
```bash
ssti-scanner report <action> [options]
```

### Actions

#### `convert` - Convert Report Formats
```bash
# Convert JSON to HTML
ssti-scanner report convert --input results.json --output report.html --format html

# Convert to CSV
ssti-scanner report convert --input results.json --output data.csv --format csv
```

#### `merge` - Merge Multiple Reports
```bash
# Merge multiple scan results
ssti-scanner report merge --input "scan_*.json" --output merged_report.json
```

#### `summary` - Generate Summary Report
```bash
# Generate executive summary
ssti-scanner report summary --input results.json --output summary.html --template executive
```

---

## `config` - Configuration Management

Manage scanner configuration and profiles.

### Syntax
```bash
ssti-scanner config <action> [options]
```

### Actions

#### `show` - Display Current Configuration
```bash
# Show current config
ssti-scanner config show

# Show specific section
ssti-scanner config show --section scanning
```

#### `set` - Set Configuration Values
```bash
# Set default values
ssti-scanner config set scanning.threads 20
ssti-scanner config set output.format json
```

#### `profile` - Manage Configuration Profiles
```bash
# Create profile
ssti-scanner config profile create --name aggressive --copy-from default

# Use profile
ssti-scanner scan --profile aggressive --url https://example.com

# List profiles
ssti-scanner config profile list
```

---

## URL File Formats

The scanner supports multiple URL file formats for batch processing.

### Simple Format
```
https://example.com/search?q=test
https://example.com/contact
https://app.example.com/profile
```

### Extended Format
```
GET https://example.com/search?q=test
POST https://example.com/contact name=test&email=test@example.com
https://example.com/profile [method=POST,data={"bio":"test"},headers={"X-Custom":"value"}]
```

### Comments and Metadata
```
# Production targets
https://example.com/search?q=test

# Staging environment
https://staging.example.com/api/search

// API endpoints
POST https://api.example.com/search [data={"query":"test"}]
```

---

## Configuration Files

### Default Configuration Location
- Linux/macOS: `~/.config/ssti-scanner/config.yml`
- Windows: `%APPDATA%\ssti-scanner\config.yml`
- Project: `./config/ssti-scanner.yml`

### Configuration Hierarchy
1. Command line arguments (highest priority)
2. Environment variables (`SSTI_*`)
3. Project configuration file
4. User configuration file
5. Default configuration (lowest priority)

### Sample Configuration
```yaml
scanning:
  threads: 10
  delay: 0.5
  timeout: 30
  intensity: normal
  follow_redirects: true

crawling:
  max_depth: 3
  max_pages: 1000
  respect_robots: true
  enable_javascript: false

detection:
  engines: []  # Empty = all engines
  blind_injection: true
  min_confidence: low

output:
  format: console
  colors: true
  verbosity: normal
  debug: false

authentication:
  type: none
  
proxy:
  http_proxy: ""
  https_proxy: ""
```

---

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | General error |
| 2 | Invalid arguments |
| 3 | Configuration error |
| 4 | Network error |
| 5 | File error |
| 10 | Vulnerabilities found (when using `--fail-on-vuln`) |

---

## Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `SSTI_CONFIG_FILE` | Configuration file path | `/path/to/config.yml` |
| `SSTI_PROXY` | Default proxy URL | `http://127.0.0.1:8080` |
| `SSTI_THREADS` | Default thread count | `20` |
| `SSTI_TIMEOUT` | Default timeout | `60` |
| `SSTI_DEBUG` | Enable debug mode | `1` |
| `SSTI_NO_COLORS` | Disable colors | `1` |

---

## Advanced Usage Examples

### CI/CD Integration
```bash
#!/bin/bash
# CI/CD security testing script

# Run quick scan for critical vulnerabilities
ssti-scanner scan \
  --file critical_endpoints.txt \
  --intensity quick \
  --format json \
  --output scan_results.json \
  --fail-on-vuln

# Convert to HTML for reporting
ssti-scanner report convert \
  --input scan_results.json \
  --output security_report.html \
  --format html

# Generate summary for notifications
ssti-scanner report summary \
  --input scan_results.json \
  --format slack \
  --webhook $SLACK_WEBHOOK
```

### Penetration Testing Workflow
```bash
# 1. Discovery phase
ssti-scanner crawl \
  --url https://target.com \
  --depth 5 \
  --include-js \
  --output crawl_data.json

# 2. Analysis phase
ssti-scanner analyze \
  --crawl-file crawl_data.json \
  --redirect-tracking \
  --output analysis.json

# 3. Testing phase
ssti-scanner scan \
  --file analysis.json \
  --intensity aggressive \
  --blind \
  --threads 20 \
  --output final_results.json

# 4. Reporting phase
ssti-scanner report convert \
  --input final_results.json \
  --output pentest_report.html \
  --template professional
```

### Custom Payload Testing
```bash
# Generate custom payloads
ssti-scanner payloads generate \
  --engine jinja2 \
  --context html \
  --evasion \
  --output custom_payloads.txt

# Test custom payloads
ssti-scanner payloads test \
  --url https://target.com/search \
  --file custom_payloads.txt \
  --output payload_results.json
```

---

## Tips and Best Practices

### Performance Optimization
- Use appropriate thread counts (`--threads`)
- Set reasonable delays (`--delay`) to avoid overwhelming targets
- Use `--intensity quick` for initial reconnaissance
- Limit crawling depth (`--crawl-depth`) for large applications

### Accuracy Improvement
- Enable blind injection testing (`--blind`) for comprehensive coverage
- Use redirect tracking for complex application flows
- Test with multiple template engines when technology stack is unknown
- Verify results manually for critical applications

### Stealth and Safety
- Use proxy chains for anonymity
- Implement request delays to avoid detection
- Respect rate limits and robots.txt when appropriate
- Never test production systems without proper authorization

### Integration
- Use JSON output format for tool integration
- Implement proper error handling in scripts
- Use configuration files for consistent settings
- Monitor exit codes for automated workflows

---

## Troubleshooting

### Common Issues

#### Connection Errors
```bash
# Use proxy for network restrictions
ssti-scanner scan --url https://example.com --proxy http://127.0.0.1:8080

# Increase timeout for slow targets
ssti-scanner scan --url https://example.com --timeout 60
```

#### Authentication Issues
```bash
# Debug authentication
ssti-scanner scan --url https://example.com --auth-type bearer --token TOKEN --debug

# Test with curl first
curl -H "Authorization: Bearer TOKEN" https://example.com
```

#### Performance Issues
```bash
# Reduce threads and increase delay
ssti-scanner scan --url https://example.com --threads 5 --delay 2.0

# Use quick intensity for faster scans
ssti-scanner scan --url https://example.com --intensity quick
```

### Debug Mode
```bash
# Enable debug logging
ssti-scanner scan --url https://example.com --debug

# Increase verbosity
ssti-scanner scan --url https://example.com --verbose
```

### Getting Help
```bash
# General help
ssti-scanner --help

# Command-specific help
ssti-scanner scan --help
ssti-scanner crawl --help

# Version information
ssti-scanner --version
```
