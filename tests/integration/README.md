# SSTI Scanner Integration Testing Framework

This directory contains a comprehensive integration testing framework for validating SSTI (Server-Side Template Injection) detection capabilities across multiple template engines and frameworks.

## Overview

The integration testing framework provides:

- **Vulnerable Web Applications**: Pre-built applications with intentional SSTI vulnerabilities for each supported template engine
- **Automated Testing**: Comprehensive test suites with payloads specific to each template engine
- **Application Management**: Automated startup, health checking, and shutdown of test applications
- **Detailed Reporting**: HTML, JSON, and CSV reports with vulnerability detection results
- **Multi-Language Support**: Applications in Python, PHP, Java, JavaScript, and Ruby

## Directory Structure

```
tests/integration/
├── vulnerable_apps/           # Vulnerable web applications organized by language
│   ├── python/               # Python applications (Flask/Jinja2, Django)
│   │   ├── jinja2_flask/     # Flask app with Jinja2 vulnerabilities
│   │   └── django_templates/ # Django app with template vulnerabilities
│   ├── php/                  # PHP applications (Twig/Symfony, Smarty)
│   │   ├── twig_symfony/     # Symfony app with Twig vulnerabilities
│   │   └── smarty/           # Smarty template vulnerabilities
│   ├── java/                 # Java applications (Spring Boot)
│   │   ├── freemarker_spring/ # Spring Boot with FreeMarker
│   │   ├── velocity_spring/   # Spring Boot with Velocity
│   │   └── thymeleaf_spring/  # Spring Boot with Thymeleaf
│   ├── javascript/           # Node.js applications
│   │   └── handlebars_express/ # Express.js with Handlebars
│   └── ruby/                 # Ruby applications
│       └── erb_rails/        # Rails app with ERB templates
├── vulnerable_app_manager.py  # Application lifecycle management
├── run_integration_tests.py   # Main test runner
├── config.ini                # Configuration settings
├── requirements.txt          # Python dependencies
└── test_results/             # Generated test reports and logs
```

## Supported Template Engines

### Python Applications
- **Jinja2 (Flask)**: Mathematical evaluation, config access, class introspection
- **Django Templates**: Filter exploitation, settings access, debug information

### PHP Applications  
- **Twig (Symfony)**: Expression evaluation, dump functions, global object access
- **Smarty**: Math functions, PHP execution, server variable access

### Java Applications
- **FreeMarker (Spring Boot)**: Class exploration, object access, static method calls
- **Velocity (Spring Boot)**: Tool object access, method invocation
- **Thymeleaf (Spring Boot)**: Expression language, utility objects

### JavaScript Applications
- **Handlebars (Express.js)**: Constructor exploitation, prototype pollution

### Ruby Applications
- **ERB (Rails)**: Ruby code execution, Rails object access

## Quick Start

### Prerequisites

1. **Python 3.8+** with pip
2. **PHP 7.4+** with Composer (for PHP apps)
3. **Java 11+** with Maven (for Java apps) 
4. **Node.js 16+** with npm (for JavaScript apps)
5. **Ruby 3.0+** with Bundler (for Ruby apps)

### Installation

1. Install Python dependencies:
```bash
cd tests/integration
pip install -r requirements.txt
```

2. Ensure all required runtime environments are installed and accessible in PATH.

### Running Tests

#### Run All Integration Tests
```bash
python run_integration_tests.py
```

#### Run Tests for Specific Engine
```bash
python run_integration_tests.py --engine jinja2
```

#### Run with Custom Configuration
```bash
python run_integration_tests.py --config custom_config.ini
```

### Test Results

After running tests, results are generated in the `test_results/` directory:

- **integration_test_results.json**: Detailed JSON results
- **integration_test_report.html**: Interactive HTML dashboard
- **integration_test_results.csv**: CSV data for analysis
- **integration_tests.log**: Detailed execution logs

## Vulnerable Applications

Each vulnerable application includes:

### Application Structure
- **Main application file** (`app.py`, `app.php`, etc.)
- **Route configuration** (`routes.py`, `routes.php`, etc.)
- **Dependency management** (`requirements.txt`, `composer.json`, `pom.xml`, etc.)
- **Template files** with vulnerable endpoints
- **Payload definitions** organized by vulnerability type

### Vulnerability Categories

#### Mathematical Evaluation
- Simple arithmetic: `{{7*7}}`, `${7*7}`, `{math equation="7*7"}`
- Complex expressions: Nested calculations and operations

#### Configuration Access
- Application config: `{{config}}`, `{{settings}}`
- Environment variables: `{{request.environ}}`
- Debug information: `{{debug}}`

#### Object Introspection
- Class exploration: `{{''.__class__.__mro__}}`
- Method access: `{{object.getClass()}}`
- Globals access: `{{lipsum.__globals__}}`

#### Code Execution
- Direct execution: `{php}echo "test";{/php}`
- Runtime access: `${Class.forName("java.lang.Runtime")}`
- System calls: Ruby `system()` calls

#### Information Disclosure
- Server variables: `{$smarty.server}`
- Request data: `{{request.META}}`
- Session data: `{{app.session}}`

## Configuration

The `config.ini` file allows customization of:

### General Settings
- Startup timeouts and delays
- Request timeouts and retry attempts
- Log levels and output options

### Port Assignments
- Unique ports for each application to avoid conflicts
- Configurable host bindings

### Security Settings
- Allowed hosts for testing
- Maximum payload lengths
- Safe mode for production environments

### Engine-Specific Settings
- Enable/disable specific engines
- Risk level classifications
- Test category selections

## API Reference

### VulnerableAppManager

Main class for managing vulnerable applications:

```python
from vulnerable_app_manager import VulnerableAppManager

# Initialize manager
manager = VulnerableAppManager(apps_directory)

# Start all applications
results = await manager.start_all()

# Health check
health = await manager.health_check_all()

# Stop all applications  
await manager.stop_all()
```

### SSTIIntegrationTester

Main testing class:

```python
from run_integration_tests import SSTIIntegrationTester

# Initialize tester
tester = SSTIIntegrationTester(apps_dir, output_dir)

# Test all applications
results = await tester.test_all_apps()

# Test specific application
app_results = await tester.test_app('jinja2_flask')
```

## Adding New Vulnerable Applications

To add support for a new template engine:

### 1. Create Application Directory
```bash
mkdir -p vulnerable_apps/language/engine_framework
```

### 2. Implement Vulnerable Application
Create the main application file with vulnerable endpoints:
- Search endpoint with user input
- Template rendering with injection points
- Debug/info endpoints
- API endpoints for evaluation

### 3. Add Route Configuration
Create `routes.py` or equivalent with:
- Payload definitions by category
- Expected response patterns
- Confidence levels

### 4. Update Application Manager
Add configuration in `vulnerable_app_manager.py`:
- Application configuration class
- Runtime-specific application class
- Port assignment and startup commands

### 5. Create Test Suite
Add test suite in `run_integration_tests.py`:
- Engine-specific payloads
- Expected response patterns
- Vulnerability indicators

## Troubleshooting

### Common Issues

#### Port Conflicts
```bash
# Check if ports are in use
netstat -tulpn | grep :5000

# Kill processes using ports
sudo lsof -ti:5000 | xargs kill -9
```

#### Missing Dependencies
```bash
# Python applications
pip install -r vulnerable_apps/python/jinja2_flask/requirements.txt

# PHP applications
cd vulnerable_apps/php/twig_symfony && composer install

# Java applications  
cd vulnerable_apps/java/freemarker_spring && mvn clean compile

# Node.js applications
cd vulnerable_apps/javascript/handlebars_express && npm install

# Ruby applications
cd vulnerable_apps/ruby/erb_rails && bundle install
```

#### Application Startup Failures
1. Check logs in `test_results/integration_tests.log`
2. Verify all dependencies are installed
3. Ensure ports are available
4. Check application-specific logs

#### Test Failures
1. Verify applications are healthy before testing
2. Check network connectivity
3. Review payload syntax for the specific engine
4. Verify expected response patterns

### Debug Mode

Enable detailed logging in `config.ini`:
```ini
[logging]
log_level = DEBUG
detailed_logging = true
```

Run with verbose output:
```bash
python run_integration_tests.py --verbose
```

## Contributing

When adding new vulnerable applications or test cases:

1. **Security**: Ensure applications are clearly marked as vulnerable and for testing only
2. **Documentation**: Update this README with new engines and vulnerability types
3. **Testing**: Verify new applications work correctly with the test framework
4. **Isolation**: Ensure applications don't interfere with each other
5. **Cleanup**: Implement proper cleanup in stop methods

## Security Considerations

⚠️ **WARNING**: The applications in this framework contain intentional security vulnerabilities.

### Safety Measures
- **Local Only**: Applications bind to localhost only
- **Test Environment**: Only run in isolated test environments
- **No Production**: Never deploy these applications to production
- **Firewall**: Ensure test ports are not accessible externally
- **Cleanup**: Always stop applications after testing

### Responsible Use
- Use only for testing SSTI detection capabilities
- Do not use against applications you don't own
- Follow responsible disclosure for any real vulnerabilities found
- Respect application security and privacy

## License

This integration testing framework is part of the SSTI Scanner project and follows the same license terms.
