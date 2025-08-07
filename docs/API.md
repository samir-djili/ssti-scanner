# API Documentation for SSTI Scanner

Welcome to the SSTI Scanner API documentation. This guide provides comprehensive information for developers who want to integrate the scanner into their applications or extend its functionality.

## Table of Contents

- [Getting Started](#getting-started)
- [Core Components](#core-components)
- [Configuration API](#configuration-api)
- [Scanner API](#scanner-api)
- [Engine API](#engine-api)
- [HTTP Client API](#http-client-api)
- [Reporter API](#reporter-api)
- [Plugin Development](#plugin-development)
- [Examples](#examples)

## Getting Started

### Installation

```bash
pip install ssti-scanner
```

### Basic Usage

```python
import asyncio
from ssti_scanner.core.scanner import SSTIScanner
from ssti_scanner.core.config import ConfigManager

async def basic_scan():
    # Create configuration
    config_manager = ConfigManager()
    config = config_manager.load_config()
    
    # Create scanner with 5-phase workflow
    scanner = SSTIScanner(config)
    
    # Scan URL using advanced 5-phase detection
    results = await scanner.scan_url("http://example.com/search?q=test")
    
    # Process results
    for result in results:
        if result.is_vulnerable:
            print(f"Vulnerability found: {result.engine_name} - {result.payload}")
            print(f"Confidence: {result.confidence_level}")
            print(f"Evidence: {result.evidence}")
    
    # Cleanup
    await scanner.close()

# Run the scan
asyncio.run(basic_scan())
```

## Core Components

### SSTIScanner

The main scanner class that orchestrates the 5-phase vulnerability detection workflow.

```python
class SSTIScanner:
    def __init__(self, config: ScanConfig)
    async def scan_url(self, url: str, **kwargs) -> List[ScanResult]
    async def scan_urls(self, urls: List[str]) -> List[ScanResult]
    async def crawl_and_scan(self, url: str, max_depth: int = 3) -> List[ScanResult]
    async def close(self) -> None
```

#### 5-Phase Scanning Workflow

The scanner implements a sophisticated 5-phase workflow:

1. **Discovery Phase**: Target analysis and parameter enumeration
2. **Analysis Phase**: Template engine fingerprinting
3. **Injection Phase**: Payload testing and vulnerability detection
4. **Correlation Phase**: Result validation and confidence scoring
5. **Finalization Phase**: Report generation and aggregation

#### Methods

##### `scan_url(url, method='GET', data=None, headers=None, **kwargs)`

Scan a single URL for SSTI vulnerabilities using the complete 5-phase workflow.

**Parameters:**
- `url` (str): Target URL to scan
- `method` (str, optional): HTTP method (GET, POST, etc.). Default: 'GET'
- `data` (dict, optional): Form data for POST requests
- `headers` (dict, optional): Custom HTTP headers
- `engines` (list, optional): Specific engines to use. Available engines:
  - `jinja2` - Jinja2 template engine (Flask, Django)
  - `twig` - Twig template engine (Symfony)
  - `freemarker` - FreeMarker template engine (Java)
  - `velocity` - Apache Velocity template engine
  - `smarty` - Smarty template engine (PHP)
  - `thymeleaf` - Thymeleaf template engine (Spring)
  - `handlebars` - Handlebars template engine (Node.js)
  - `django` - Django Templates (Django framework)
  - `erb` - ERB template engine (Ruby on Rails)
- `intensity` (str, optional): Scan intensity ('quick', 'normal', 'aggressive')

**Returns:**
- `List[ScanResult]`: List of scan results

**Example:**
```python
# GET request
results = await scanner.scan_url("http://example.com/search?q=test")

# POST request with data
results = await scanner.scan_url(
    "http://example.com/submit",
    method="POST",
    data={"field": "value"},
    headers={"Content-Type": "application/x-www-form-urlencoded"}
)

# Custom engine selection
results = await scanner.scan_url(
    "http://example.com/test",
    engines=["jinja2", "twig"]
)
```

##### `scan_urls(urls, **kwargs)`

Scan multiple URLs concurrently.

**Parameters:**
- `urls` (List[str]): List of URLs to scan
- `**kwargs`: Same optional parameters as `scan_url`

**Returns:**
- `List[ScanResult]`: Combined results from all URLs

**Example:**
```python
urls = [
    "http://example.com/page1",
    "http://example.com/page2",
    "http://example.com/page3"
]

results = await scanner.scan_urls(urls)
```

### ScanResult

Data class representing a scan result.

```python
@dataclass
class ScanResult:
    url: str
    is_vulnerable: bool
    confidence: ConfidenceLevel
    engine: str
    payload: str
    response: str
    evidence: str
    timestamp: datetime
    metadata: Dict[str, Any]
```

**Properties:**
- `url`: The scanned URL
- `is_vulnerable`: Whether a vulnerability was detected
- `confidence`: Confidence level (LOW, MEDIUM, HIGH)
- `engine`: Template engine that detected the vulnerability
- `payload`: The payload that triggered the vulnerability
- `response`: Server response that indicated vulnerability
- `evidence`: Human-readable evidence description
- `timestamp`: When the test was performed
- `metadata`: Additional metadata about the test

## Configuration API

### ConfigManager

Manages scanner configuration from multiple sources.

```python
class ConfigManager:
    def __init__(self, config_file: str = None)
    def get_config(self) -> ScanConfig
    def get_profile_config(self, profile: str) -> ScanConfig
    def update_config(self, key: str, value: Any) -> None
    def save_config(self, file_path: str) -> None
```

#### Methods

##### `get_config()`

Get the current configuration.

**Returns:**
- `ScanConfig`: Current configuration object

##### `get_profile_config(profile)`

Get configuration for a specific profile.

**Parameters:**
- `profile` (str): Profile name ('quick', 'normal', 'aggressive', 'stealth')

**Returns:**
- `ScanConfig`: Profile-specific configuration

**Example:**
```python
config_manager = ConfigManager()

# Get default config
config = config_manager.get_config()

# Get aggressive scan profile
aggressive_config = config_manager.get_profile_config('aggressive')
```

##### `update_config(key, value)`

Update a configuration value at runtime.

**Parameters:**
- `key` (str): Configuration key (e.g., 'scanning.threads')
- `value` (Any): New value

**Example:**
```python
config_manager = ConfigManager()

# Update thread count
config_manager.update_config('scanning.threads', 20)

# Update output format
config_manager.update_config('output.format', 'json')
```

### ScanConfig

Configuration data class with all scanner settings.

```python
@dataclass
class ScanConfig:
    scanning: ScanningConfig
    crawling: CrawlingConfig
    detection: DetectionConfig
    output: OutputConfig
    authentication: AuthConfig
    proxy: ProxyConfig
```

#### Configuration Sections

##### ScanningConfig
```python
@dataclass
class ScanningConfig:
    threads: int = 10
    delay: float = 0.5
    timeout: int = 30
    intensity: str = 'normal'
    follow_redirects: bool = True
    max_redirects: int = 5
```

##### DetectionConfig
```python
@dataclass
class DetectionConfig:
    engines: List[str] = field(default_factory=list)  # Empty = all engines
    min_confidence: str = 'low'
    blind_injection: bool = False
    context_analysis: bool = True
```

##### OutputConfig
```python
@dataclass
class OutputConfig:
    format: str = 'console'  # console, json, html, csv
    colors: bool = True
    verbosity: str = 'normal'  # quiet, normal, verbose
    debug: bool = False
```

## Scanner API

### Advanced Scanning Methods

#### Context-Aware Scanning

```python
async def scan_with_context(scanner, url, context_type):
    """Scan with specific context awareness."""
    
    results = await scanner.scan_url(
        url,
        context=context_type,  # 'html', 'url', 'attribute', 'json'
        adaptive_payloads=True
    )
    
    return results
```

#### Form-Specific Scanning

```python
async def scan_form(scanner, form_url, form_data):
    """Scan form submissions for SSTI."""
    
    results = await scanner.scan_url(
        form_url,
        method="POST",
        data=form_data,
        analyze_forms=True
    )
    
    return results
```

#### Blind Injection Testing

```python
async def scan_blind(scanner, url):
    """Perform blind injection testing."""
    
    results = await scanner.scan_url(
        url,
        blind_injection=True,
        time_based=True,
        dns_based=False  # Requires DNS server setup
    )
    
    return results
```

## Engine API

### BaseTemplateEngine

Abstract base class for template engines.

```python
class BaseTemplateEngine:
    def __init__(self, config: ScanConfig)
    async def test_payload(self, url: str, payload: str, **kwargs) -> EngineResult
    def analyze_response(self, original: str, payload: str, response: str) -> EngineResult
    def get_payloads_for_context(self, context: str) -> List[Payload]
```

### Creating Custom Engines

```python
from ssti_scanner.engines.base import BaseTemplateEngine, EngineResult, ConfidenceLevel

class CustomEngine(BaseTemplateEngine):
    def __init__(self, config):
        super().__init__(config)
        self.name = "custom_engine"
        self.payloads = self._load_payloads()
    
    def _load_payloads(self):
        """Load engine-specific payloads."""
        return [
            Payload("${7*7}", "math", "html", "Basic math operation"),
            Payload("${class.inspect}", "code_execution", "html", "Class introspection"),
            # Add more payloads...
        ]
    
    async def test_payload(self, url, payload, **kwargs):
        """Test a single payload against the target."""
        http_client = kwargs.get('http_client')
        
        # Inject payload into URL or data
        test_url = url.replace('INJECT', payload)
        
        try:
            response = await http_client.get(test_url)
            return self.analyze_response("", payload, response['text'])
        except Exception as e:
            return EngineResult(
                is_vulnerable=False,
                confidence=ConfidenceLevel.LOW,
                payload=payload,
                response="",
                evidence=f"Error: {e}",
                engine=self.name
            )
    
    def analyze_response(self, original, payload, response):
        """Analyze response for vulnerability indicators."""
        
        # Custom analysis logic
        if payload == "${7*7}" and "49" in response:
            return EngineResult(
                is_vulnerable=True,
                confidence=ConfidenceLevel.HIGH,
                payload=payload,
                response=response,
                evidence="Mathematical operation executed",
                engine=self.name
            )
        
        return EngineResult(
            is_vulnerable=False,
            confidence=ConfidenceLevel.LOW,
            payload=payload,
            response=response,
            evidence="No vulnerability indicators found",
            engine=self.name
        )

# Register the custom engine
from ssti_scanner.engines.factory import EngineFactory
EngineFactory.register_engine("custom", CustomEngine)
```

## HTTP Client API

### HTTPClient

Async HTTP client with built-in rate limiting and error handling.

```python
class HTTPClient:
    def __init__(self, config: ScanConfig)
    async def get(self, url: str, **kwargs) -> Dict[str, Any]
    async def post(self, url: str, **kwargs) -> Dict[str, Any]
    async def request(self, method: str, url: str, **kwargs) -> Dict[str, Any]
    async def close(self) -> None
```

#### Methods

##### `get(url, **kwargs)`

Perform HTTP GET request.

**Parameters:**
- `url` (str): Target URL
- `headers` (dict, optional): Custom headers
- `cookies` (dict, optional): Cookies to send
- `params` (dict, optional): URL parameters
- `timeout` (int, optional): Request timeout
- `follow_redirects` (bool, optional): Follow redirects

**Returns:**
- `Dict[str, Any]`: Response dictionary with keys:
  - `status`: HTTP status code
  - `text`: Response text
  - `headers`: Response headers
  - `url`: Final URL (after redirects)
  - `redirected`: Whether request was redirected
  - `json`: Parsed JSON (if applicable)

**Example:**
```python
client = HTTPClient(config)

# Basic GET
response = await client.get("http://example.com")

# GET with parameters
response = await client.get(
    "http://example.com/search",
    params={"q": "test"},
    headers={"User-Agent": "Custom-Agent"}
)

# Check response
if response['status'] == 200:
    print(f"Response: {response['text']}")

await client.close()
```

##### `post(url, **kwargs)`

Perform HTTP POST request.

**Parameters:**
- `url` (str): Target URL
- `data` (dict, optional): Form data
- `json` (dict, optional): JSON data
- `headers` (dict, optional): Custom headers
- `files` (dict, optional): File uploads

**Example:**
```python
# Form data POST
response = await client.post(
    "http://example.com/submit",
    data={"field1": "value1", "field2": "value2"}
)

# JSON POST
response = await client.post(
    "http://api.example.com/endpoint",
    json={"key": "value"},
    headers={"Content-Type": "application/json"}
)
```

## Reporter API

### BaseReporter

Abstract base class for result reporters.

```python
class BaseReporter:
    def __init__(self, config: ScanConfig)
    async def generate_report(self, results: List[ScanResult]) -> None
    def format_result(self, result: ScanResult) -> str
```

### Built-in Reporters

#### ConsoleReporter

```python
from ssti_scanner.reporters.console import ConsoleReporter

reporter = ConsoleReporter(config)
await reporter.generate_report(results)
```

#### JSONReporter

```python
from ssti_scanner.reporters.json import JSONReporter

reporter = JSONReporter(config)
await reporter.generate_report(results)
```

#### HTMLReporter

```python
from ssti_scanner.reporters.html import HTMLReporter

reporter = HTMLReporter(config)
await reporter.generate_report(results)
```

### Custom Reporters

```python
from ssti_scanner.reporters.base import BaseReporter

class CustomReporter(BaseReporter):
    def __init__(self, config):
        super().__init__(config)
        self.output_file = "custom_report.txt"
    
    async def generate_report(self, results):
        """Generate custom format report."""
        
        with open(self.output_file, 'w') as f:
            f.write("SSTI Scan Report\n")
            f.write("================\n\n")
            
            vulnerable_results = [r for r in results if r.is_vulnerable]
            
            f.write(f"Summary:\n")
            f.write(f"- Total tests: {len(results)}\n")
            f.write(f"- Vulnerabilities: {len(vulnerable_results)}\n\n")
            
            for result in vulnerable_results:
                f.write(self.format_result(result))
                f.write("\n" + "-"*50 + "\n")
    
    def format_result(self, result):
        """Format individual result."""
        return f"""
URL: {result.url}
Engine: {result.engine}
Payload: {result.payload}
Confidence: {result.confidence.value}
Evidence: {result.evidence}
"""
```

## Plugin Development

### Engine Plugins

Create a new file `my_engine.py`:

```python
from ssti_scanner.engines.base import BaseTemplateEngine, EngineResult, ConfidenceLevel, Payload

class MyTemplateEngine(BaseTemplateEngine):
    def __init__(self, config):
        super().__init__(config)
        self.name = "my_engine"
        self.payloads = self._load_payloads()
    
    def _load_payloads(self):
        return [
            Payload("{%7*7%}", "math", "html", "Math operation"),
            Payload("{%config%}", "config_access", "html", "Config access"),
            # Add more payloads
        ]
    
    async def test_payload(self, url, payload, **kwargs):
        # Implementation
        pass
    
    def analyze_response(self, original, payload, response):
        # Implementation
        pass

# Register the engine
def register_engine():
    from ssti_scanner.engines.factory import EngineFactory
    EngineFactory.register_engine("my_engine", MyTemplateEngine)

# Auto-register when module is imported
register_engine()
```

### Reporter Plugins

Create a new file `my_reporter.py`:

```python
from ssti_scanner.reporters.base import BaseReporter

class MyCustomReporter(BaseReporter):
    def __init__(self, config):
        super().__init__(config)
    
    async def generate_report(self, results):
        # Custom report generation
        pass
    
    def format_result(self, result):
        # Custom result formatting
        pass

# Register the reporter
def register_reporter():
    from ssti_scanner.reporters.factory import ReporterFactory
    ReporterFactory.register_reporter("my_reporter", MyCustomReporter)

register_reporter()
```

## Examples

### Complete Scanning Workflow

```python
import asyncio
from ssti_scanner import SSTIScanner, ConfigManager
from ssti_scanner.reporters.console import ConsoleReporter

async def complete_scan_workflow():
    """Complete scanning workflow example."""
    
    # Configuration
    config_manager = ConfigManager()
    config = config_manager.get_config()
    
    # Customize settings
    config.scanning.threads = 15
    config.scanning.intensity = 'aggressive'
    config.detection.blind_injection = True
    
    # Create scanner and reporter
    scanner = SSTIScanner(config)
    reporter = ConsoleReporter(config)
    
    try:
        # Define targets
        targets = [
            {"url": "http://example.com/search", "method": "GET"},
            {"url": "http://example.com/submit", "method": "POST", "data": {"field": "test"}},
        ]
        
        all_results = []
        
        # Scan each target
        for target in targets:
            print(f"Scanning: {target['url']}")
            
            results = await scanner.scan_url(**target)
            all_results.extend(results)
        
        # Generate report
        await reporter.generate_report(all_results)
        
        # Summary
        vuln_count = sum(1 for r in all_results if r.is_vulnerable)
        print(f"\nScan completed: {vuln_count} vulnerabilities found")
        
    finally:
        await scanner.close()

# Run the workflow
asyncio.run(complete_scan_workflow())
```

### Authenticated Scanning

```python
async def authenticated_scan():
    """Example of scanning with authentication."""
    
    config_manager = ConfigManager()
    config = config_manager.get_config()
    
    # Configure authentication
    config.authentication.type = 'bearer'
    config.authentication.token = 'your-jwt-token'
    
    scanner = SSTIScanner(config)
    
    # Custom headers for authentication
    headers = {
        'Authorization': 'Bearer your-jwt-token',
        'X-API-Key': 'your-api-key'
    }
    
    results = await scanner.scan_url(
        "http://api.example.com/protected",
        headers=headers
    )
    
    await scanner.close()
    return results
```

### Batch Processing

```python
async def batch_processing():
    """Process multiple URL lists."""
    
    from ssti_scanner.input.url_list_processor import URLListProcessor
    
    processor = URLListProcessor()
    config_manager = ConfigManager()
    scanner = SSTIScanner(config_manager.get_config())
    
    # Load URLs from file
    urls = processor.load_from_file("targets.txt")
    
    # Process in batches
    batch_size = 10
    all_results = []
    
    for i in range(0, len(urls), batch_size):
        batch = urls[i:i + batch_size]
        batch_urls = [url.url for url in batch]
        
        print(f"Processing batch {i//batch_size + 1}")
        results = await scanner.scan_urls(batch_urls)
        all_results.extend(results)
    
    await scanner.close()
    return all_results
```

## Error Handling

### Common Exceptions

```python
from ssti_scanner.exceptions import (
    SSTIError,
    ConfigurationError,
    NetworkError,
    EngineError
)

try:
    results = await scanner.scan_url("http://example.com")
except NetworkError as e:
    print(f"Network error: {e}")
except EngineError as e:
    print(f"Engine error: {e}")
except ConfigurationError as e:
    print(f"Configuration error: {e}")
except SSTIError as e:
    print(f"General SSTI error: {e}")
```

### Graceful Error Handling

```python
async def robust_scanning(scanner, urls):
    """Robust scanning with error handling."""
    
    results = []
    errors = []
    
    for url in urls:
        try:
            url_results = await scanner.scan_url(url)
            results.extend(url_results)
        except Exception as e:
            errors.append({"url": url, "error": str(e)})
            continue
    
    return results, errors
```

## Performance Optimization

### Concurrency Control

```python
# Optimize thread count based on target
config.scanning.threads = min(20, len(urls))

# Adjust delays for rate limiting
config.scanning.delay = 1.0  # 1 second between requests

# Set appropriate timeouts
config.scanning.timeout = 60  # 60 second timeout
```

### Memory Management

```python
# Process large URL lists in chunks
async def process_large_list(scanner, urls, chunk_size=100):
    for i in range(0, len(urls), chunk_size):
        chunk = urls[i:i + chunk_size]
        results = await scanner.scan_urls(chunk)
        
        # Process results immediately
        process_results(results)
        
        # Clear memory
        del results
```

### Connection Pooling

```python
# HTTP client automatically handles connection pooling
# Adjust pool size if needed
config.http.max_connections = 100
config.http.max_connections_per_host = 20
```

This API documentation provides comprehensive coverage of the SSTI Scanner's programmatic interface. For more examples and advanced usage patterns, see the examples directory in the project repository.
