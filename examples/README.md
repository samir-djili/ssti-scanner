# SSTI Scanner Examples

This directory contains practical examples and tutorials for using the SSTI Scanner with all 9 implemented template engines.

## Template Engine Examples

### Jinja2 (Python/Flask)
- `jinja2_basic.py` - Basic Jinja2 vulnerability detection
- `jinja2_advanced.py` - Flask application context exploitation
- `jinja2_blind.py` - Blind injection techniques

### Twig (PHP/Symfony) 
- `twig_basic.py` - Mathematical expression detection
- `twig_filter.py` - Filter-based exploitation
- `twig_object.py` - Object disclosure techniques

### FreeMarker (Java)
- `freemarker_basic.py` - Class.forName exploitation
- `freemarker_reflection.py` - Java reflection attacks
- `freemarker_spring.py` - Spring Boot context access

### Velocity (Apache)
- `velocity_basic.py` - VTL syntax exploitation
- `velocity_tools.py` - VelocityTools access
- `velocity_directive.py` - Directive execution

### Smarty (PHP)
- `smarty_basic.py` - Mathematical evaluation
- `smarty_functions.py` - PHP function execution
- `smarty_variables.py` - Server variable access

### Thymeleaf (Spring)
- `thymeleaf_basic.py` - Expression language exploitation
- `thymeleaf_spring.py` - Spring context access
- `thymeleaf_utils.py` - Utility object exploitation

### Handlebars (Node.js)
- `handlebars_basic.py` - Constructor exploitation
- `handlebars_helpers.py` - Helper function abuse
- `handlebars_node.py` - Node.js globals access

### Django Templates
- `django_basic.py` - Filter chain exploitation
- `django_debug.py` - Debug information disclosure
- `django_settings.py` - Settings access

### ERB (Ruby/Rails)
- `erb_basic.py` - Ruby code execution
- `erb_system.py` - System command execution
- `erb_rails.py` - Rails object access

## Basic Examples

### [basic_scan.py](basic_scan.py)
Simple single-URL scanning example showing the most basic usage across all engines.

### [file_input.py](file_input.py)
Demonstrates scanning multiple URLs from various file formats with all template engines.

### [configuration.py](configuration.py)
Shows different configuration options and profiles for comprehensive engine coverage.

## Advanced Examples

### [custom_engine.py](custom_engine.py)
Example of creating a custom template engine plugin extending the base engine architecture.

### [advanced_scanning.py](advanced_scanning.py)
Comprehensive scanning with crawling, form analysis, and reporting across all 9 engines.

### [authentication.py](authentication.py)
Examples of authenticated scanning with various auth methods for protected template endpoints.

### [ci_cd_integration.py](ci_cd_integration.py)
CI/CD pipeline integration example with multi-engine vulnerability detection.

## Configuration Examples

### [configs/](configs/)
Sample configuration files for different use cases:
- `quick_scan.yml` - Fast reconnaissance configuration (all engines, minimal payloads)
- `comprehensive.yml` - Thorough security testing configuration (all engines, extensive payloads)
- `stealth.yml` - Low-profile scanning configuration (selective engines, stealth timing)
- `production.yml` - Production-safe scanning settings (safe payloads only)
- `engine_specific.yml` - Individual engine configurations

## URL List Examples

### [url_lists/](url_lists/)
Sample URL list files in different formats:
- `simple_urls.txt` - Simple URL list format
- `extended_urls.txt` - Extended format with methods and data
- `burp_export.xml` - Burp Suite export format
- `zap_export.json` - OWASP ZAP export format
- `engine_targets.txt` - URLs categorized by likely template engine

## Vulnerable Test Applications

### [test_apps/](test_apps/)
Simple vulnerable applications for testing:
- `flask_jinja2.py` - Flask application with Jinja2 SSTI vulnerability
- `express_handlebars.js` - Express.js with Handlebars vulnerability
- `spring_freemarker.java` - Spring Boot with FreeMarker vulnerability

## Integration Examples

### [integrations/](integrations/)
Examples of integrating with other tools:
- `burp_integration.py` - Burp Suite plugin integration
- `zap_integration.py` - OWASP ZAP script integration
- `jenkins_pipeline.groovy` - Jenkins pipeline example
- `github_actions.yml` - GitHub Actions workflow

## Usage Scenarios

Each example includes:
- Complete, runnable code
- Detailed comments explaining key concepts
- Sample input/output files
- Configuration options
- Error handling best practices

## Running Examples

```bash
# Navigate to examples directory
cd examples

# Install dependencies
pip install -r requirements.txt

# Run basic example
python basic_scan.py

# Run with custom configuration
python advanced_scanning.py --config configs/comprehensive.yml
```

## Prerequisites

All examples assume you have:
1. Python 3.8+ installed
2. SSTI Scanner package installed (`pip install -e .` from project root)
3. Network connectivity for external targets (when applicable)
4. Appropriate permissions for scanning target applications

## Safety Notice

⚠️ **WARNING**: Only run these examples against applications you own or have explicit permission to test. Unauthorized security testing may violate laws and regulations in your jurisdiction.

## Contributing Examples

To contribute new examples:
1. Create a new Python file with descriptive name
2. Include comprehensive comments and docstrings
3. Add sample input/output files if needed
4. Update this README with description
5. Test thoroughly before submitting PR
