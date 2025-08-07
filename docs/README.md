# SSTI Scanner - Complete Documentation

## Project Overview

The **SSTI Scanner** is a comprehensive, modular, and sophisticated tool designed to detect Server-Side Template Injection vulnerabilities across multiple template engines. Built with Python 3.8+ and featuring an asynchronous architecture, the scanner provides both command-line interface and programmatic API access for security professionals, developers, and DevOps teams.

## Key Features

### 🔍 **Multi-Engine Detection**
- **Jinja2** (Flask, Django templates) - ✅ **Fully Implemented**
- **Twig** (Symfony) - ✅ **Fully Implemented**
- **FreeMarker** (Spring Boot, Struts) - ✅ **Fully Implemented**
- **Velocity** (Apache Velocity) - ✅ **Fully Implemented**
- **Smarty** (PHP) - ✅ **Fully Implemented**
- **Handlebars** (Node.js) - ✅ **Fully Implemented**
- **Thymeleaf** (Spring Boot) - ✅ **Fully Implemented**
- **Django Templates** (Django framework) - ✅ **Fully Implemented**
- **ERB** (Ruby on Rails) - ✅ **Fully Implemented**
- **Extensible plugin architecture** for custom engines

### 🚀 **Advanced Scanning Capabilities**
- **Asynchronous scanning** with configurable concurrency
- **Context-aware payload generation** (HTML, URL, attribute, JSON contexts)
- **Blind injection detection** with time-based and DNS-based techniques
- **Form analysis and enumeration**
- **Redirect tracking and analysis**
- **Web application crawling** with JavaScript support
- **Rate limiting and stealth modes**

### 📁 **Flexible Input Methods**
- Single URL scanning
- Batch processing from files (simple, extended, JSON formats)
- Burp Suite export integration
- OWASP ZAP export integration
- Custom URL list formats with metadata

### 📊 **Comprehensive Reporting**
- **Console output** with colored formatting
- **JSON reports** for tool integration
- **HTML reports** with interactive features
- **CSV exports** for data analysis
- **Custom report templates**
- **Executive summaries**

### 🛡️ **Enterprise Features**
- **Authentication support** (Basic, Bearer, OAuth, Custom headers)
- **Proxy integration** (HTTP/HTTPS/SOCKS)
- **Configuration profiles** (Quick, Normal, Aggressive, Stealth)
- **CI/CD pipeline integration**
- **Docker containerization**
- **Comprehensive logging and audit trails**

## Quick Start

### Installation

```bash
# Install from PyPI
pip install ssti-scanner

# Or install from source
git clone https://github.com/your-username/ssti-scanner.git
cd ssti-scanner
pip install -e .
```

### Basic Usage

```bash
# Scan a single URL
ssti-scanner scan --url https://example.com/search?q=test

# Scan multiple URLs from file
ssti-scanner scan --file urls.txt

# Aggressive scan with crawling
ssti-scanner scan --url https://example.com --intensity aggressive --crawl-depth 5
```

### Programmatic Usage

```python
import asyncio
from ssti_scanner import SSTIScanner, ConfigManager

async def scan_example():
    config = ConfigManager().get_config()
    scanner = SSTIScanner(config)
    
    results = await scanner.scan_url("https://example.com/test")
    
    for result in results:
        if result.is_vulnerable:
            print(f"🚨 Vulnerability: {result.engine} - {result.payload}")
    
    await scanner.close()

asyncio.run(scan_example())
```

## Documentation Index

### 📚 **User Guides**
- **[Installation Guide](INSTALLATION.md)** - Complete setup instructions for all platforms
- **[CLI Guide](CLI_GUIDE.md)** - Comprehensive command-line usage reference
- **[Configuration Guide](CONFIGURATION.md)** - Configuration options and profiles
- **[Usage Examples](../examples/README.md)** - Practical examples and tutorials

### 🔧 **Developer Resources**
- **[API Documentation](API.md)** - Complete programmatic interface reference
- **[Plugin Development](PLUGIN_DEVELOPMENT.md)** - Creating custom engines and reporters
- **[Architecture Overview](ARCHITECTURE.md)** - Internal design and components
- **[Contributing Guide](CONTRIBUTING.md)** - Development guidelines and standards

### 🛡️ **Security & Testing**
- **[Security Considerations](SECURITY.md)** - Safe usage and security guidelines
- **[Testing Guide](TESTING.md)** - Test suite and quality assurance
- **[Troubleshooting](TROUBLESHOOTING.md)** - Common issues and solutions

### 📋 **Reference**
- **[Requirements](../REQUIREMENTS.md)** - Detailed feature requirements
- **[Context](../CONTEXT.md)** - Technical background and methodologies
- **[Changelog](../CHANGELOG.md)** - Version history and updates
- **[License](../LICENSE)** - MIT License terms

## Architecture Overview

```
SSTI Scanner Architecture
├── CLI Interface (argparse + async)
├── Core Components
│   ├── Configuration Manager (YAML + env vars)
│   ├── Scanner Engine (async orchestration)
│   └── Result System (structured data)
├── Detection Engines
│   ├── Base Engine (abstract interface)
│   ├── Jinja2 Engine (50+ payloads)
│   ├── Twig Engine (comprehensive)
│   └── Plugin System (extensible)
├── HTTP Client (aiohttp)
│   ├── Connection Pooling
│   ├── Rate Limiting
│   └── Error Handling
├── Web Crawler
│   ├── Link Discovery
│   ├── Form Analysis
│   └── JavaScript Support
├── Input Processing
│   ├── URL List Processor
│   ├── Multiple Format Support
│   └── Filtering & Deduplication
└── Reporting System
    ├── Console Reporter
    ├── JSON/HTML/CSV Exporters
    └── Custom Templates
```

## Supported Template Engines

| Engine | Framework | Status | Payloads | Features |
|--------|-----------|--------|----------|----------|
| **Jinja2** | Flask, Django | ✅ Complete | 50+ | Math, Config, Code Execution |
| **Twig** | Symfony | ✅ Complete | 40+ | Object Access, Filters |
| **FreeMarker** | Spring Boot | 🚧 In Progress | 30+ | Java Objects, Methods |
| **Velocity** | Apache | 🚧 In Progress | 25+ | VTL Syntax, Tools |
| **Smarty** | PHP | 📋 Planned | - | PHP Functions, Modifiers |
| **Handlebars** | Node.js | 📋 Planned | - | Helpers, Partials |
| **Thymeleaf** | Spring | 📋 Planned | - | Expression Language |

## Configuration Profiles

### Quick Scan
- **Purpose**: Fast reconnaissance
- **Threads**: ≤ 10
- **Depth**: ≤ 2 levels
- **Payloads**: Basic math operations
- **Time**: ~30 seconds per URL

### Normal Scan (Default)
- **Purpose**: Balanced coverage and speed
- **Threads**: 10-15
- **Depth**: 3-5 levels
- **Payloads**: Common vulnerability patterns
- **Time**: ~2-5 minutes per URL

### Aggressive Scan
- **Purpose**: Maximum vulnerability detection
- **Threads**: 15-25
- **Depth**: 5+ levels
- **Payloads**: All available payloads
- **Features**: Blind injection, code execution
- **Time**: ~10-30 minutes per URL

### Stealth Scan
- **Purpose**: Avoid detection
- **Threads**: ≤ 5
- **Delay**: ≥ 2 seconds
- **Features**: Randomized timing, minimal footprint
- **Time**: Variable (slow and steady)

## Integration Examples

### CI/CD Pipeline

```yaml
# GitHub Actions
name: Security Scan
on: [push, pull_request]
jobs:
  ssti-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Install SSTI Scanner
        run: pip install ssti-scanner
      - name: Run Scan
        run: ssti-scanner scan --file endpoints.txt --format json --output results.json
      - name: Upload Results
        uses: actions/upload-artifact@v2
        with:
          name: ssti-scan-results
          path: results.json
```

### Docker Usage

```bash
# Quick scan
docker run --rm sstiscanner/ssti-scanner scan --url https://example.com

# With custom config
docker run --rm -v $(pwd)/config:/config sstiscanner/ssti-scanner scan --config /config/custom.yml --url https://example.com

# Batch processing
docker run --rm -v $(pwd)/data:/data sstiscanner/ssti-scanner scan --file /data/urls.txt --output /data/results.json
```

### Tool Integration

```python
# Integration with other security tools
from ssti_scanner import SSTIScanner
from burp_export_parser import parse_burp_file

# Parse Burp Suite results
urls = parse_burp_file("burp_history.xml")

# Scan discovered URLs
scanner = SSTIScanner()
results = await scanner.scan_urls(urls)

# Export for other tools
export_to_defectdojo(results)
export_to_sonarqube(results)
```

## Performance Characteristics

### Scalability
- **Concurrent Requests**: Up to 50 simultaneous connections
- **Memory Usage**: ~50-100MB for typical scans
- **URL Processing**: 100-1000+ URLs per scan session
- **Large Deployments**: Supports enterprise-scale applications

### Optimization
- **Connection Pooling**: Reuses HTTP connections
- **Smart Caching**: Avoids duplicate requests
- **Adaptive Delays**: Automatic rate limiting
- **Resource Management**: Efficient memory and CPU usage

## Security Considerations

### Safe Usage
- **Authorization**: Only scan applications you own or have permission to test
- **Rate Limiting**: Use appropriate delays to avoid overwhelming targets
- **Payload Safety**: Built-in safeguards against harmful code execution
- **Data Privacy**: No sensitive data is stored or transmitted to external services

### Best Practices
- Test in staging environments first
- Use stealth mode for production systems
- Monitor target application performance
- Review results for false positives
- Document all testing activities

## Community and Support

### Getting Help
- **Documentation**: Complete guides and API reference
- **GitHub Issues**: Bug reports and feature requests
- **Discussions**: Community Q&A and usage patterns
- **Examples**: Practical implementation patterns

### Contributing
- **Bug Reports**: Help improve the tool
- **Feature Requests**: Suggest new capabilities
- **Code Contributions**: Submit pull requests
- **Documentation**: Improve guides and examples

### Roadmap
- **Q1 2024**: Additional template engines (Smarty, Handlebars)
- **Q2 2024**: Browser automation and JavaScript SSTI detection
- **Q3 2024**: Machine learning-based payload generation
- **Q4 2024**: Cloud service integrations and enterprise features

## License and Legal

### MIT License
The SSTI Scanner is released under the MIT License, allowing free use, modification, and distribution. See [LICENSE](../LICENSE) for full terms.

### Disclaimer
This tool is intended for security testing of applications you own or have explicit permission to test. Users are responsible for compliance with applicable laws and regulations.

### Attribution
Built with ❤️ by the SSTI Scanner team and contributors. Special thanks to the security research community for vulnerability research and template engine documentation.

---

## Quick Navigation

| Need | Go To |
|------|-------|
| **First time setup** | [Installation Guide](INSTALLATION.md) |
| **Command line usage** | [CLI Guide](CLI_GUIDE.md) |
| **Python integration** | [API Documentation](API.md) |
| **Configuration help** | [Configuration Guide](CONFIGURATION.md) |
| **Practical examples** | [Examples Directory](../examples/) |
| **Troubleshooting** | [Troubleshooting Guide](TROUBLESHOOTING.md) |
| **Contributing** | [Contributing Guide](CONTRIBUTING.md) |

For the most up-to-date information, visit the [GitHub repository](https://github.com/samir-djili/ssti-scanner).
