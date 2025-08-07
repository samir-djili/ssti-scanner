"""
Test configuration and utilities for the SSTI scanner test suite.
"""

import asyncio
import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock

import pytest
import aiohttp
from aiohttp import web
from aiohttp.test_utils import TestServer

# Test constants
TEST_BASE_URL = "http://localhost:8080"
TEST_TIMEOUT = 5.0
TEST_USER_AGENT = "SSTI-Scanner-Test/1.0"

# Mock vulnerable responses
VULNERABLE_RESPONSES = {
    "jinja2": {
        "{{7*7}}": "49",
        "{{config}}": "<Config",
        "{{request}}": "<Request",
        "{{''.__class__.__mro__[2].__subclasses__()}}": "[<class 'type'>, <class 'weakref'>",
    },
    "twig": {
        "{{7*7}}": "49",
        "{{dump(app)}}": "object(Symfony\\Bundle\\FrameworkBundle\\FrameworkBundle)",
        "{{_self}}": "Template",
    },
    "freemarker": {
        "${7*7}": "49",
        "${product.class}": "class java.lang",
        "${''.getClass()}": "class java.lang.String",
    },
    "velocity": {
        "#set($x=7*7)$x": "49",
        "$class.inspect": "java.lang.Class",
    },
    "smarty": {
        "{7*7}": "49",
        "{php}echo 'test';{/php}": "test",
    }
}

# Non-vulnerable responses (should not trigger detection)
SAFE_RESPONSES = {
    "{{7*7}}": "{{7*7}}",  # Literal template syntax
    "${7*7}": "${7*7}",
    "{7*7}": "{7*7}",
    "#set($x=7*7)$x": "#set($x=7*7)$x",
}

class MockWebServer:
    """Mock web server for testing SSTI detection."""
    
    def __init__(self):
        self.app = web.Application()
        self.server: Optional[TestServer] = None
        self.vulnerable_endpoints = {}
        self.form_endpoints = {}
        self.redirect_endpoints = {}
        self.setup_routes()
    
    def setup_routes(self):
        """Setup test routes."""
        # Basic vulnerable endpoint
        self.app.router.add_get('/vulnerable', self.vulnerable_handler)
        self.app.router.add_post('/vulnerable', self.vulnerable_handler)
        
        # Safe endpoint
        self.app.router.add_get('/safe', self.safe_handler)
        self.app.router.add_post('/safe', self.safe_handler)
        
        # Form endpoints
        self.app.router.add_get('/form', self.form_handler)
        self.app.router.add_post('/form/submit', self.form_submit_handler)
        
        # Redirect endpoints
        self.app.router.add_get('/redirect', self.redirect_handler)
        self.app.router.add_get('/redirect/target', self.redirect_target_handler)
        
        # Custom endpoints for specific tests
        self.app.router.add_get('/custom/{path:.*}', self.custom_handler)
        self.app.router.add_post('/custom/{path:.*}', self.custom_handler)
    
    async def vulnerable_handler(self, request):
        """Handler that reflects payloads vulnerably."""
        # Get payload from query params or form data
        payload = None
        
        if request.method == 'GET':
            payload = request.query.get('q', request.query.get('search', ''))
        elif request.method == 'POST':
            data = await request.post()
            payload = data.get('q', data.get('search', ''))
        
        # Check if payload matches known vulnerable patterns
        for engine, patterns in VULNERABLE_RESPONSES.items():
            if payload in patterns:
                response_body = f"Search results for: {patterns[payload]}"
                return web.Response(text=response_body, content_type='text/html')
        
        # Default response
        return web.Response(text=f"Search results for: {payload}", content_type='text/html')
    
    async def safe_handler(self, request):
        """Handler that safely handles input."""
        payload = request.query.get('q', 'default')
        # Always return the payload literally (safe behavior)
        return web.Response(text=f"Safe results for: {payload}", content_type='text/html')
    
    async def form_handler(self, request):
        """Handler that returns an HTML form."""
        form_html = '''
        <html>
        <body>
            <form method="post" action="/form/submit">
                <input type="text" name="username" placeholder="Username">
                <input type="password" name="password" placeholder="Password">
                <textarea name="bio" placeholder="Biography"></textarea>
                <select name="country">
                    <option value="us">United States</option>
                    <option value="uk">United Kingdom</option>
                </select>
                <input type="submit" value="Submit">
            </form>
            <form method="get" action="/search">
                <input type="text" name="q" placeholder="Search">
                <button type="submit">Search</button>
            </form>
        </body>
        </html>
        '''
        return web.Response(text=form_html, content_type='text/html')
    
    async def form_submit_handler(self, request):
        """Handler for form submission."""
        data = await request.post()
        bio = data.get('bio', '')
        
        # Bio field is vulnerable
        for engine, patterns in VULNERABLE_RESPONSES.items():
            if bio in patterns:
                response = f"Profile updated. Bio: {patterns[bio]}"
                return web.Response(text=response, content_type='text/html')
        
        return web.Response(text=f"Profile updated. Bio: {bio}", content_type='text/html')
    
    async def redirect_handler(self, request):
        """Handler that redirects to another endpoint."""
        target = request.query.get('target', '/redirect/target')
        return web.Response(status=302, headers={'Location': target})
    
    async def redirect_target_handler(self, request):
        """Target of redirect that may be vulnerable."""
        payload = request.query.get('data', '')
        
        # Check for vulnerability
        for engine, patterns in VULNERABLE_RESPONSES.items():
            if payload in patterns:
                response = f"Redirected result: {patterns[payload]}"
                return web.Response(text=response, content_type='text/html')
        
        return web.Response(text=f"Redirected result: {payload}", content_type='text/html')
    
    async def custom_handler(self, request):
        """Custom handler for specific test scenarios."""
        path = request.match_info['path']
        
        # Custom endpoint configurations
        if path in self.vulnerable_endpoints:
            config = self.vulnerable_endpoints[path]
            param = config.get('param', 'q')
            
            if request.method == 'GET':
                payload = request.query.get(param, '')
            else:
                data = await request.post()
                payload = data.get(param, '')
            
            # Return vulnerable response if configured
            engine = config.get('engine', 'jinja2')
            if engine in VULNERABLE_RESPONSES and payload in VULNERABLE_RESPONSES[engine]:
                response = VULNERABLE_RESPONSES[engine][payload]
                return web.Response(text=f"Result: {response}", content_type='text/html')
        
        return web.Response(text="Not found", status=404)
    
    def add_vulnerable_endpoint(self, path: str, engine: str = 'jinja2', param: str = 'q'):
        """Add a custom vulnerable endpoint."""
        self.vulnerable_endpoints[path] = {
            'engine': engine,
            'param': param
        }
    
    async def start(self, port: int = 8080):
        """Start the mock server."""
        self.server = TestServer(self.app, port=port)
        await self.server.start_server()
        return self.server
    
    async def stop(self):
        """Stop the mock server."""
        if self.server:
            await self.server.close()

class TestURLProcessor:
    """Helper for creating test URL lists."""
    
    @staticmethod
    def create_simple_list(urls: List[str]) -> str:
        """Create a simple URL list."""
        return '\n'.join(urls)
    
    @staticmethod
    def create_extended_list(entries: List[Dict[str, Any]]) -> str:
        """Create an extended format URL list."""
        lines = []
        for entry in entries:
            url = entry['url']
            method = entry.get('method', 'GET')
            
            if method != 'GET' or entry.get('data') or entry.get('headers'):
                line = f"{method} {url}"
                metadata = []
                
                if 'data' in entry:
                    if isinstance(entry['data'], dict):
                        data_str = json.dumps(entry['data'])
                        metadata.append(f'data={data_str}')
                    else:
                        metadata.append(f'data={entry["data"]}')
                
                if 'headers' in entry:
                    headers_str = json.dumps(entry['headers'])
                    metadata.append(f'headers={headers_str}')
                
                if metadata:
                    line += f" [{','.join(metadata)}]"
                
                lines.append(line)
            else:
                lines.append(url)
        
        return '\n'.join(lines)

class TestResultCollector:
    """Helper for collecting and analyzing test results."""
    
    def __init__(self):
        self.results = []
        self.vulnerabilities = []
        self.errors = []
    
    def add_result(self, result: Dict[str, Any]):
        """Add a scan result."""
        self.results.append(result)
        
        if result.get('is_vulnerable', False):
            self.vulnerabilities.append(result)
    
    def add_error(self, error: str):
        """Add an error."""
        self.errors.append(error)
    
    def get_vulnerability_count(self) -> int:
        """Get total vulnerability count."""
        return len(self.vulnerabilities)
    
    def get_engines_found(self) -> List[str]:
        """Get list of vulnerable engines found."""
        engines = set()
        for vuln in self.vulnerabilities:
            if 'engine' in vuln:
                engines.add(vuln['engine'])
        return list(engines)
    
    def has_vulnerability_for_url(self, url: str) -> bool:
        """Check if URL has vulnerabilities."""
        for vuln in self.vulnerabilities:
            if vuln.get('url') == url:
                return True
        return False

@pytest.fixture
async def mock_server():
    """Pytest fixture for mock web server."""
    server = MockWebServer()
    await server.start()
    yield server
    await server.stop()

@pytest.fixture
def temp_urls_file():
    """Pytest fixture for temporary URL list file."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        yield f.name
    Path(f.name).unlink(missing_ok=True)

@pytest.fixture
def temp_config_file():
    """Pytest fixture for temporary config file."""
    config = {
        'scanning': {
            'threads': 5,
            'delay': 0.1,
            'timeout': 5
        },
        'detection': {
            'engines': ['jinja2', 'twig'],
            'min_confidence': 'low'
        }
    }
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
        import yaml
        yaml.dump(config, f)
        yield f.name
    Path(f.name).unlink(missing_ok=True)

@pytest.fixture
def result_collector():
    """Pytest fixture for result collection."""
    return TestResultCollector()

# Async test helpers
def async_test(func):
    """Decorator for async test functions."""
    def wrapper(*args, **kwargs):
        return asyncio.run(func(*args, **kwargs))
    return wrapper

# Mock HTTP client
class MockHTTPClient:
    """Mock HTTP client for testing."""
    
    def __init__(self):
        self.responses = {}
        self.request_log = []
    
    def set_response(self, url: str, response_text: str, status: int = 200):
        """Set mock response for URL."""
        self.responses[url] = {
            'text': response_text,
            'status': status,
            'headers': {'Content-Type': 'text/html'}
        }
    
    async def get(self, url: str, **kwargs) -> Dict[str, Any]:
        """Mock GET request."""
        self.request_log.append(('GET', url, kwargs))
        
        if url in self.responses:
            return self.responses[url]
        
        return {
            'text': 'Not Found',
            'status': 404,
            'headers': {}
        }
    
    async def post(self, url: str, **kwargs) -> Dict[str, Any]:
        """Mock POST request."""
        self.request_log.append(('POST', url, kwargs))
        
        if url in self.responses:
            return self.responses[url]
        
        return {
            'text': 'Not Found',
            'status': 404,
            'headers': {}
        }
    
    def get_request_count(self) -> int:
        """Get total request count."""
        return len(self.request_log)
    
    def get_requests_for_url(self, url: str) -> List[tuple]:
        """Get all requests for specific URL."""
        return [req for req in self.request_log if req[1] == url]

# Test data generators
def generate_test_urls(count: int = 10) -> List[str]:
    """Generate test URLs."""
    return [f"http://test{i}.example.com/page?id={i}" for i in range(count)]

def generate_vulnerable_urls(engines: List[str] = None) -> List[str]:
    """Generate URLs that should be detected as vulnerable."""
    if engines is None:
        engines = ['jinja2', 'twig', 'freemarker']
    
    urls = []
    for i, engine in enumerate(engines):
        urls.append(f"http://vuln{i}.example.com/search?engine={engine}")
    
    return urls

def generate_form_data(include_vulnerable: bool = True) -> Dict[str, str]:
    """Generate form data for testing."""
    data = {
        'username': 'testuser',
        'email': 'test@example.com',
        'bio': 'Test biography'
    }
    
    if include_vulnerable:
        data['bio'] = '{{7*7}}'  # Vulnerable payload
    
    return data
