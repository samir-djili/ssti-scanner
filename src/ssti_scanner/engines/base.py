"""
Base classes for template engine detection.

This module defines the abstract base classes and common functionality
for all template engine detection plugins.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Set, Pattern, Any

from ssti_scanner.utils.http_client import HTTPResponse


class ConfidenceLevel(Enum):
    """Confidence levels for vulnerability detection."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"


class VulnerabilityType(Enum):
    """Types of SSTI vulnerabilities."""
    INFORMATION_DISCLOSURE = "information_disclosure"
    FILE_ACCESS = "file_access"
    CODE_EXECUTION = "code_execution"
    BLIND_INJECTION = "blind_injection"


@dataclass
class DetectionResult:
    """Result of template engine detection."""
    engine_name: str
    confidence: ConfidenceLevel
    vulnerability_type: VulnerabilityType
    payload: str
    evidence: str
    description: str
    impact: str = ""
    remediation: str = ""
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class TemplateEngine(ABC):
    """
    Abstract base class for template engine detection.
    
    Each template engine plugin should inherit from this class and implement
    the required methods for detection and exploitation.
    """
    
    def __init__(self, name: str):
        self.name = name
        self.signatures: List[Pattern] = []
        self.error_patterns: List[Pattern] = []
        self.payloads: Dict[VulnerabilityType, List[str]] = {}
        self.response_indicators: Dict[str, Pattern] = {}
        
        self._initialize_patterns()
        self._initialize_payloads()
    
    @abstractmethod
    def _initialize_patterns(self) -> None:
        """Initialize engine-specific detection patterns."""
        pass
    
    @abstractmethod
    def _initialize_payloads(self) -> None:
        """Initialize engine-specific payloads."""
        pass
    
    @abstractmethod
    def get_context_payloads(self, context: str) -> List[str]:
        """Get payloads suitable for a specific context."""
        pass
    
    def detect_engine(self, response: HTTPResponse) -> Optional[DetectionResult]:
        """
        Detect if this template engine is in use based on response.
        
        Args:
            response: HTTP response to analyze
            
        Returns:
            DetectionResult if engine detected, None otherwise
        """
        # Check for error patterns first (high confidence)
        for pattern in self.error_patterns:
            if pattern.search(response.text):
                return DetectionResult(
                    engine_name=self.name,
                    confidence=ConfidenceLevel.HIGH,
                    vulnerability_type=VulnerabilityType.INFORMATION_DISCLOSURE,
                    payload="error_based_detection",
                    evidence=pattern.pattern,
                    description=f"{self.name} template engine detected via error message"
                )
        
        # Check for signature patterns (medium confidence)
        for pattern in self.signatures:
            if pattern.search(response.text):
                return DetectionResult(
                    engine_name=self.name,
                    confidence=ConfidenceLevel.MEDIUM,
                    vulnerability_type=VulnerabilityType.INFORMATION_DISCLOSURE,
                    payload="signature_detection",
                    evidence=pattern.pattern,
                    description=f"{self.name} template engine detected via signature"
                )
        
        return None
    
    def test_vulnerability(self, payload: str, response: HTTPResponse) -> Optional[DetectionResult]:
        """
        Test if a payload resulted in successful injection.
        
        Args:
            payload: The payload that was sent
            response: HTTP response received
            
        Returns:
            DetectionResult if vulnerability detected, None otherwise
        """
        # Check for mathematical expression evaluation
        if self._check_math_evaluation(payload, response):
            return DetectionResult(
                engine_name=self.name,
                confidence=ConfidenceLevel.CONFIRMED,
                vulnerability_type=VulnerabilityType.CODE_EXECUTION,
                payload=payload,
                evidence=f"Mathematical expression evaluated in response",
                description=f"Confirmed SSTI vulnerability in {self.name}",
                impact="Remote code execution possible",
                remediation="Sanitize user input before template processing"
            )
        
        # Check for configuration disclosure
        if self._check_config_disclosure(payload, response):
            return DetectionResult(
                engine_name=self.name,
                confidence=ConfidenceLevel.HIGH,
                vulnerability_type=VulnerabilityType.INFORMATION_DISCLOSURE,
                payload=payload,
                evidence="Configuration information disclosed",
                description=f"Information disclosure via {self.name} template injection",
                impact="Application configuration and sensitive data exposure",
                remediation="Disable debug mode and sanitize template variables"
            )
        
        # Check for error-based detection
        error_result = self._check_template_errors(payload, response)
        if error_result:
            return error_result
        
        return None
    
    def _check_math_evaluation(self, payload: str, response: HTTPResponse) -> bool:
        """Check if mathematical expressions were evaluated."""
        # Common math tests
        math_tests = [
            (r'7\*7', '49'),
            (r'8\*8', '64'),
            (r'9\*9', '81'),
            (r'7\*\'7\'', '7777777'),
            (r'8\*\'8\'', '88888888'),
        ]
        
        for expr, expected in math_tests:
            if re.search(expr, payload) and expected in response.text:
                return True
        
        return False
    
    def _check_config_disclosure(self, payload: str, response: HTTPResponse) -> bool:
        """Check for configuration information disclosure."""
        config_indicators = [
            'SECRET_KEY',
            'DATABASE_URL',
            'DEBUG',
            'SQLALCHEMY_DATABASE_URI',
            'FLASK_ENV',
            'config',
            'settings',
            'environment'
        ]
        
        for indicator in config_indicators:
            if indicator.lower() in response.text.lower():
                return True
        
        return False
    
    def _check_template_errors(self, payload: str, response: HTTPResponse) -> Optional[DetectionResult]:
        """Check for template engine error messages."""
        for pattern in self.error_patterns:
            match = pattern.search(response.text)
            if match:
                return DetectionResult(
                    engine_name=self.name,
                    confidence=ConfidenceLevel.HIGH,
                    vulnerability_type=VulnerabilityType.INFORMATION_DISCLOSURE,
                    payload=payload,
                    evidence=match.group(0),
                    description=f"Template error indicates {self.name} vulnerability",
                    impact="Information disclosure and potential code execution",
                    remediation="Implement proper error handling and input validation"
                )
        
        return None
    
    def get_basic_payloads(self) -> List[str]:
        """Get basic detection payloads for this engine."""
        basic_payloads = []
        for vuln_type, payloads in self.payloads.items():
            basic_payloads.extend(payloads[:3])  # Take first 3 from each type
        return basic_payloads
    
    def get_advanced_payloads(self) -> List[str]:
        """Get advanced exploitation payloads for this engine."""
        advanced_payloads = []
        if VulnerabilityType.CODE_EXECUTION in self.payloads:
            advanced_payloads.extend(self.payloads[VulnerabilityType.CODE_EXECUTION])
        return advanced_payloads
    
    def get_blind_payloads(self) -> List[str]:
        """Get payloads for blind injection testing."""
        if VulnerabilityType.BLIND_INJECTION in self.payloads:
            return self.payloads[VulnerabilityType.BLIND_INJECTION]
        return []
    
    def estimate_payload_success(self, payload: str, context: str) -> float:
        """
        Estimate the probability of payload success in given context.
        
        Args:
            payload: The payload to evaluate
            context: The injection context (html, attr, js, etc.)
            
        Returns:
            Success probability between 0.0 and 1.0
        """
        # Base probability
        probability = 0.5
        
        # Adjust based on payload complexity
        if len(payload) < 20:
            probability += 0.2  # Simple payloads more likely to work
        elif len(payload) > 100:
            probability -= 0.3  # Complex payloads less likely
        
        # Adjust based on context
        context_adjustments = {
            'html': 0.1,
            'attr': -0.1,
            'js': -0.2,
            'css': -0.3,
            'url': 0.0
        }
        
        probability += context_adjustments.get(context, 0.0)
        
        # Ensure probability is within bounds
        return max(0.0, min(1.0, probability))
    
    def get_evasion_variants(self, payload: str) -> List[str]:
        """
        Generate evasion variants of a payload.
        
        Args:
            payload: Original payload
            
        Returns:
            List of evasion variants
        """
        variants = [payload]  # Include original
        
        # URL encoding
        import urllib.parse
        variants.append(urllib.parse.quote(payload))
        
        # HTML entity encoding for special characters
        html_encoded = payload.replace('{', '&#123;').replace('}', '&#125;')
        variants.append(html_encoded)
        
        # Case variations (for case-insensitive contexts)
        if payload.lower() != payload:
            variants.append(payload.lower())
        if payload.upper() != payload:
            variants.append(payload.upper())
        
        # Whitespace variations
        variants.append(payload.replace(' ', '\t'))
        variants.append(payload.replace(' ', '\n'))
        
        return variants
    
    def __str__(self) -> str:
        return f"TemplateEngine({self.name})"
    
    def __repr__(self) -> str:
        return self.__str__()
