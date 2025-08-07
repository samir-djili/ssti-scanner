# SSTI Scanner

A sophisticated, modular Python-based Server-Side Template Injection (SSTI) vulnerability scanner designed for security professionals and penetration testers.

## 🎯 Overview

Server-Side Template Injection (SSTI) vulnerabilities occur when user input is embedded in templates unsafely, potentially allowing attackers to execute arbitrary code. This scanner provides comprehensive detection capabilities across multiple template engines with an intuitive command-line interface and a powerful 5-phase scanning workflow.

## ✨ Features

### Core Capabilities
- 🔍 **Multi-Engine Support**: Detects SSTI vulnerabilities across 9 template engines
- 🎯 **Smart Detection**: Uses multiple techniques including mathematical evaluation, object disclosure, and error-based detection
- 🚀 **High Performance**: 5-phase scanning workflow with concurrent processing and intelligent batching
- 📊 **Comprehensive Reporting**: Multiple output formats (JSON, HTML, CSV, XML, Console)
- 🔧 **Modular Architecture**: Plugin-based system for easy extension and customization
- 🌐 **Web Crawler**: Integrated crawler for automatic form and parameter discovery
- 🧠 **Intelligence Engine**: Advanced payload generation with context-aware injection
- 🛡️ **False Positive Mitigation**: Multi-layered validation and confidence scoring

### Supported Template Engines
- **Python**: Jinja2, Django Templates
- **PHP**: Twig, Smarty  
- **Java**: FreeMarker, Velocity, Thymeleaf
- **JavaScript**: Handlebars
- **Ruby**: ERB

### Detection Techniques
- **Mathematical Expression Evaluation**: Primary detection method using `{{7*7}}` → `49`
- **Object/Variable Disclosure**: Accessing template engine internals
- **Filter/Function Execution**: Testing built-in template functions
- **Error-Based Fingerprinting**: Analyzing template engine error messages
- **Context-Aware Testing**: URL parameters, form fields, headers, cookies
- **Framework Integration**: Spring, Symfony, Rails-specific vectors
- **Advanced Exploitation**: Code execution, file access, system disclosure

## 🏗️ Scanner Architecture

The SSTI Scanner follows a comprehensive 5-phase scanning workflow:

### Phase 1: Discovery & Crawling
- Target URL discovery and enumeration
- Form analysis and parameter identification
- HTTP method detection (GET/POST)
- Authentication context preservation

### Phase 2: Analysis & Fingerprinting  
- Template engine fingerprinting
- Injection point classification
- Context analysis (HTML, URL, attribute, JavaScript)
- Security control detection

### Phase 3: Payload Generation & Injection
- Engine-specific payload generation
- Context-aware payload encoding
- Concurrent payload testing with rate limiting
- Response collection and preprocessing

### Phase 4: Detection & Correlation
- Multi-pattern response analysis
- Confidence level calculation
- False positive elimination
- Cross-engine validation

### Phase 5: Reporting & Finalization
- Vulnerability consolidation
- Risk assessment and scoring
- Report generation in multiple formats
- Cleanup and resource management

## 🚀 Quick Start

### Installation
```bash
# Clone the repository
git clone https://github.com/samir-djili/ssti-scanner.git
cd ssti-scanner

# Install dependencies
pip install -r requirements.txt

# Install the package
pip install -e .
```

### Basic Usage
```bash
# Scan a single URL
ssti-scanner scan -u https://example.com/search?q=test

# Scan multiple URLs from file
ssti-scanner scan -f urls.txt

# Scan with web crawling
ssti-scanner crawl-scan -u https://example.com --max-depth 3

# Aggressive scan with detailed output
ssti-scanner scan -u https://example.com --intensity aggressive --output report.json

# Scan specific template engines only
ssti-scanner scan -u https://example.com --engines jinja2,twig

# List available engines
ssti-scanner list-engines

# Generate scan report
ssti-scanner report -i scan_results.json -o report.html --format html
```

## 📁 Project Structure

```
ssti-scanner/
├── docs/                   # Documentation
│   ├── API.md             # API documentation
│   ├── CLI_GUIDE.md       # Command-line interface guide
│   ├── INSTALLATION.md    # Installation instructions
│   └── README.md          # Documentation overview
├── src/
│   ├── ssti_scanner/
│   │   ├── cli/           # Command-line interface
│   │   │   ├── commands.py
│   │   │   └── main.py
│   │   ├── core/          # Core scanning engine
│   │   │   ├── config.py
│   │   │   ├── engine_manager.py
│   │   │   ├── form_analyzer.py
│   │   │   ├── result.py
│   │   │   ├── result_correlator.py
│   │   │   └── scanner.py
│   │   ├── crawler/       # Web crawler
│   │   │   └── web_crawler.py
│   │   ├── detectors/     # Detection engine
│   │   │   └── detection_engine.py
│   │   ├── engines/       # Template engine plugins
│   │   │   ├── base.py
│   │   │   ├── django_engine.py
│   │   │   ├── engine_factory.py
│   │   │   ├── erb_engine.py
│   │   │   ├── freemarker_engine.py
│   │   │   ├── handlebars_engine.py
│   │   │   ├── jinja2_engine.py
│   │   │   ├── smarty_engine.py
│   │   │   ├── thymeleaf_engine.py
│   │   │   ├── twig_engine.py
│   │   │   └── velocity_engine.py
│   │   ├── input/         # Input processing
│   │   │   └── url_list_processor.py
│   │   ├── payloads/      # Payload management
│   │   │   ├── context_analyzer.py
│   │   │   ├── payload_generator.py
│   │   │   └── payload_manager.py
│   │   ├── reporters/     # Output formatting
│   │   │   ├── base_reporter.py
│   │   │   ├── console_reporter.py
│   │   │   ├── csv_reporter.py
│   │   │   ├── html_reporter.py
│   │   │   ├── json_reporter.py
│   │   │   ├── reporter_factory.py
│   │   │   └── xml_reporter.py
│   │   └── utils/         # Utility functions
│   │       ├── http_client.py
│   │       └── logger.py
├── tests/                 # Test suite
├── examples/              # Usage examples
│   ├── basic_scan.py     # Basic scanning example
│   └── README.md         # Examples documentation
├── CONTEXT.md            # Technical context and background
├── PROJECT_STRUCTURE.md  # Detailed project structure
├── REQUIREMENTS.md       # Detailed requirements
└── README.md             # This file
```

## 🔧 Configuration

The scanner supports configuration through:
- Command-line arguments
- Configuration files (YAML/JSON)
- Environment variables

Example configuration:
```yaml
# config.yaml
scan:
  timeout: 30
  threads: 10
  delay: 0.5
  
engines:
  - jinja2
  - twig
  - freemarker
  
output:
  format: json
  file: scan_results.json
  verbose: true
```

## 🧪 Testing

The project includes comprehensive test coverage:

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=ssti_scanner

# Run specific test categories
pytest tests/unit/
pytest tests/integration/
```

## 📖 Documentation

- [REQUIREMENTS.md](REQUIREMENTS.md) - Detailed functional and technical requirements
- [CONTEXT.md](CONTEXT.md) - Technical background and SSTI vulnerability context
- [API Documentation](docs/api.md) - Detailed API reference
- [Plugin Development](docs/plugins.md) - Guide for extending the scanner

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is intended for authorized security testing only. Users are responsible for ensuring they have proper authorization before testing any systems. The authors are not responsible for any misuse of this tool.

## 🔗 Resources

- [OWASP Template Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection)
- [PortSwigger SSTI Research](https://portswigger.net/research/server-side-template-injection)
- [Template Engine Security](https://blog.portswigger.net/2015/08/server-side-template-injection.html)

## 📞 Support

- 🐛 [Report Issues](https://github.com/samir-djili/ssti-scanner/issues)
- 💬 [Discussions](https://github.com/samir-djili/ssti-scanner/discussions)
- 📧 Email: [ns_djili@esi.dz]

---

Built with ❤️ for the security community