"""
Detection Engine for SSTI Scanner.

This module provides the main detection engine that orchestrates SSTI vulnerability
detection across multiple template engines and coordinates payload testing.
"""

import logging
from typing import List, Dict, Any, Optional, Set
from urllib.parse import urljoin
import asyncio
import aiohttp

from ..engines.engine_factory import EngineFactory
from ..engines.base_template_engine import BaseTemplateEngine, TemplateEngine


class DetectionEngine:
    """
    Main detection engine that orchestrates SSTI vulnerability testing.
    
    This class manages the detection workflow by:
    1. Identifying potential injection points
    2. Testing payloads across multiple template engines
    3. Analyzing responses for vulnerability indicators
    4. Correlating results to minimize false positives
    """
    
    def __init__(self, session: Optional[aiohttp.ClientSession] = None):
        """
        Initialize the detection engine.
        
        Args:
            session: HTTP session for making requests
        """
        self.logger = logging.getLogger(__name__)
        self.session = session
        self.engine_factory = EngineFactory()
        self.engines = self.engine_factory.create_all_engines()
        self.detected_vulnerabilities = []
        
    async def detect_ssti(self, url: str, parameters: Dict[str, str],
                         headers: Optional[Dict[str, str]] = None,
                         cookies: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
        """
        Detect SSTI vulnerabilities in the given URL with parameters.
        
        Args:
            url: Target URL to test
            parameters: Dictionary of parameters to test
            headers: Optional HTTP headers
            cookies: Optional cookies
            
        Returns:
            List of detected vulnerabilities with details
        """
        vulnerabilities = []
        
        # Test each parameter for SSTI
        for param_name, param_value in parameters.items():
            self.logger.info(f"Testing parameter '{param_name}' for SSTI")
            
            # Test against each template engine
            for engine in self.engines:
                try:
                    results = await self._test_parameter_with_engine(
                        url, param_name, param_value, engine, headers, cookies
                    )
                    
                    if results:
                        vulnerabilities.extend(results)
                        
                except Exception as e:
                    self.logger.error(f"Error testing {param_name} with {engine.name}: {e}")
                    
        return self._deduplicate_vulnerabilities(vulnerabilities)
    
    async def _test_parameter_with_engine(self, url: str, param_name: str,
                                        original_value: str, engine: BaseTemplateEngine,
                                        headers: Optional[Dict[str, str]] = None,
                                        cookies: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
        """
        Test a specific parameter with a specific template engine.
        
        Args:
            url: Target URL
            param_name: Parameter name to test
            original_value: Original parameter value
            engine: Template engine to test with
            headers: HTTP headers
            cookies: Cookies
            
        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []
        
        # Get baseline response
        baseline_response = await self._make_request(
            url, {param_name: original_value}, headers, cookies
        )
        
        if not baseline_response:
            return vulnerabilities
            
        # Test with engine-specific payloads
        test_payloads = engine.get_test_payloads()
        
        for payload_info in test_payloads:
            payload = payload_info['payload']
            expected_output = payload_info.get('expected_output')
            
            # Make request with payload
            test_response = await self._make_request(
                url, {param_name: payload}, headers, cookies
            )
            
            if not test_response:
                continue
                
            # Analyze response for vulnerability
            is_vulnerable, confidence, details = engine.analyze_response(
                test_response, baseline_response, payload, expected_output
            )
            
            if is_vulnerable:
                vulnerability = {
                    'url': url,
                    'parameter': param_name,
                    'engine': engine.name,
                    'payload': payload,
                    'expected_output': expected_output,
                    'confidence': confidence,
                    'details': details,
                    'response_content': test_response.get('content', '')[:1000],  # Truncate
                    'response_status': test_response.get('status_code'),
                    'response_headers': test_response.get('headers', {}),
                    'baseline_content': baseline_response.get('content', '')[:1000]
                }
                
                vulnerabilities.append(vulnerability)
                self.logger.warning(
                    f"SSTI vulnerability detected: {engine.name} in {param_name} "
                    f"with confidence {confidence}"
                )
                
        return vulnerabilities
    
    async def _make_request(self, url: str, params: Dict[str, str],
                          headers: Optional[Dict[str, str]] = None,
                          cookies: Optional[Dict[str, str]] = None) -> Optional[Dict[str, Any]]:
        """
        Make HTTP request with given parameters.
        
        Args:
            url: Target URL
            params: Parameters to send
            headers: HTTP headers
            cookies: Cookies
            
        Returns:
            Response information or None if request failed
        """
        if not self.session:
            return None
            
        try:
            # Try both GET and POST methods
            response_info = None
            
            # Try GET request first
            async with self.session.get(
                url,
                params=params,
                headers=headers,
                cookies=cookies,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                content = await response.text()
                response_info = {
                    'content': content,
                    'status_code': response.status,
                    'headers': dict(response.headers),
                    'method': 'GET'
                }
                
                # If GET doesn't reflect parameters, try POST
                if not any(param in content for param in params.values()):
                    async with self.session.post(
                        url,
                        data=params,
                        headers=headers,
                        cookies=cookies,
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as post_response:
                        post_content = await post_response.text()
                        
                        # Use POST response if it reflects parameters better
                        if any(param in post_content for param in params.values()):
                            response_info = {
                                'content': post_content,
                                'status_code': post_response.status,
                                'headers': dict(post_response.headers),
                                'method': 'POST'
                            }
                            
            return response_info
            
        except Exception as e:
            self.logger.error(f"Request failed for {url}: {e}")
            return None
    
    def _deduplicate_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Remove duplicate vulnerabilities based on URL, parameter, and engine.
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            
        Returns:
            Deduplicated list of vulnerabilities
        """
        seen = set()
        unique_vulnerabilities = []
        
        for vuln in vulnerabilities:
            key = (vuln['url'], vuln['parameter'], vuln['engine'])
            if key not in seen:
                seen.add(key)
                unique_vulnerabilities.append(vuln)
                
        return unique_vulnerabilities
    
    async def quick_scan(self, url: str, parameters: Dict[str, str]) -> bool:
        """
        Perform a quick scan to determine if SSTI is likely present.
        
        Args:
            url: Target URL
            parameters: Parameters to test
            
        Returns:
            True if SSTI is likely present, False otherwise
        """
        # Use only fast detection engines for quick scan
        quick_engines = [
            engine for engine in self.engines 
            if engine.name in ['jinja2', 'twig', 'smarty']
        ]
        
        for param_name, param_value in parameters.items():
            for engine in quick_engines:
                # Test with basic math payload
                math_payload = engine.get_basic_payload()
                if not math_payload:
                    continue
                    
                test_response = await self._make_request(
                    url, {param_name: math_payload}, None, None
                )
                
                if test_response:
                    is_vulnerable, _, _ = engine.analyze_response(
                        test_response, None, math_payload, None
                    )
                    
                    if is_vulnerable:
                        return True
                        
        return False
    
    def get_supported_engines(self) -> List[str]:
        """
        Get list of supported template engine names.
        
        Returns:
            List of engine names
        """
        return [engine.name for engine in self.engines]
    
    def get_engine_by_name(self, engine_name: str) -> Optional[BaseTemplateEngine]:
        """
        Get template engine instance by name.
        
        Args:
            engine_name: Name of the engine
            
        Returns:
            Engine instance or None if not found
        """
        for engine in self.engines:
            if engine.name == engine_name:
                return engine
        return None
    
    async def test_specific_payload(self, url: str, param_name: str, 
                                  payload: str, engine_name: Optional[str] = None) -> Dict[str, Any]:
        """
        Test a specific payload against a parameter.
        
        Args:
            url: Target URL
            param_name: Parameter name
            payload: Payload to test
            engine_name: Specific engine to use (optional)
            
        Returns:
            Test results
        """
        engines_to_test = []
        
        if engine_name:
            engine = self.get_engine_by_name(engine_name)
            if engine:
                engines_to_test = [engine]
        else:
            engines_to_test = self.engines
            
        results = {
            'payload': payload,
            'parameter': param_name,
            'url': url,
            'engine_results': []
        }
        
        for engine in engines_to_test:
            test_response = await self._make_request(
                url, {param_name: payload}, None, None
            )
            
            if test_response:
                is_vulnerable, confidence, details = engine.analyze_response(
                    test_response, None, payload, None
                )
                
                results['engine_results'].append({
                    'engine': engine.name,
                    'vulnerable': is_vulnerable,
                    'confidence': confidence,
                    'details': details
                })
                
        return results
    
    def close(self):
        """Close the detection engine and cleanup resources."""
        self.logger.info("Detection engine closed")
        # Additional cleanup if needed
