"""
Payload manager for SSTI Scanner.

This module manages payload generation, selection, and optimization
based on target analysis and historical success patterns.
"""

from __future__ import annotations

import random
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass

from ssti_scanner.engines.base import TemplateEngine, VulnerabilityType
from ssti_scanner.engines.engine_factory import EngineFactory


@dataclass
class PayloadResult:
    """Result of payload execution."""
    payload: str
    success: bool
    confidence: float
    response_time: float
    evidence: str = ""
    engine_detected: str = ""


class PayloadManager:
    """
    Manages payload generation and selection for SSTI testing.
    
    Features:
    - Context-aware payload selection
    - Success pattern learning
    - Adaptive payload generation
    - Performance optimization
    """
    
    def __init__(self):
        self.engines = EngineFactory.create_all_engines()
        self.success_history: Dict[str, List[PayloadResult]] = {}
        self.context_success_rates: Dict[str, Dict[str, float]] = {}
        
    def get_detection_payloads(self, 
                             target_engines: Optional[List[str]] = None,
                             intensity: str = "normal") -> List[str]:
        """
        Get payloads for initial template engine detection.
        
        Args:
            target_engines: Specific engines to target, None for all
            intensity: Scan intensity (quick, normal, aggressive)
            
        Returns:
            List of detection payloads
        """
        payloads = []
        
        # Filter engines if specified
        engines = self.engines
        if target_engines:
            engines = [e for e in engines if e.name.lower() in 
                      [t.lower() for t in target_engines]]
        
        # Get basic payloads from each engine
        for engine in engines:
            if intensity == "quick":
                engine_payloads = engine.get_basic_payloads()[:2]
            elif intensity == "normal":
                engine_payloads = engine.get_basic_payloads()[:5]
            else:  # aggressive
                engine_payloads = engine.get_basic_payloads()
            
            payloads.extend(engine_payloads)
        
        # Add common detection payloads
        common_payloads = [
            "{{7*7}}",
            "${7*7}",
            "{7*7}",
            "<%=7*7%>",
            "#{7*7}",
            "{{7*'7'}}",
            "${7*'7'}",
            "{7*'7'}",
        ]
        
        payloads.extend(common_payloads)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_payloads = []
        for payload in payloads:
            if payload not in seen:
                seen.add(payload)
                unique_payloads.append(payload)
        
        return unique_payloads
    
    def get_context_payloads(self, 
                           context: str,
                           engine_name: Optional[str] = None) -> List[str]:
        """
        Get payloads optimized for specific injection context.
        
        Args:
            context: Injection context (html, attr, js, css, url)
            engine_name: Specific engine to target
            
        Returns:
            List of context-optimized payloads
        """
        payloads = []
        
        if engine_name:
            engine = EngineFactory.create_engine(engine_name)
            if engine:
                payloads.extend(engine.get_context_payloads(context))
        else:
            for engine in self.engines:
                payloads.extend(engine.get_context_payloads(context))
        
        # Sort by historical success rate for this context
        if context in self.context_success_rates:
            success_rates = self.context_success_rates[context]
            payloads.sort(key=lambda p: success_rates.get(p, 0.5), reverse=True)
        
        return payloads
    
    def get_exploitation_payloads(self, 
                                engine_name: str,
                                vuln_type: VulnerabilityType) -> List[str]:
        """
        Get exploitation payloads for confirmed vulnerability.
        
        Args:
            engine_name: Name of detected template engine
            vuln_type: Type of vulnerability to exploit
            
        Returns:
            List of exploitation payloads
        """
        engine = EngineFactory.create_engine(engine_name)
        if not engine:
            return []
        
        if vuln_type in engine.payloads:
            return engine.payloads[vuln_type]
        
        return []
    
    def get_blind_payloads(self, engine_name: Optional[str] = None) -> List[str]:
        """
        Get payloads for blind SSTI detection.
        
        Args:
            engine_name: Specific engine to target
            
        Returns:
            List of blind detection payloads
        """
        payloads = []
        
        if engine_name:
            engine = EngineFactory.create_engine(engine_name)
            if engine:
                payloads.extend(engine.get_blind_payloads())
        else:
            for engine in self.engines:
                payloads.extend(engine.get_blind_payloads())
        
        return payloads
    
    def get_evasion_payloads(self, 
                           original_payload: str,
                           engine_name: Optional[str] = None) -> List[str]:
        """
        Generate evasion variants of a payload.
        
        Args:
            original_payload: Original payload to create variants for
            engine_name: Specific engine context
            
        Returns:
            List of evasion payload variants
        """
        variants = [original_payload]
        
        if engine_name:
            engine = EngineFactory.create_engine(engine_name)
            if engine:
                variants.extend(engine.get_evasion_variants(original_payload))
        else:
            # Generic evasion techniques
            import urllib.parse
            
            # URL encoding
            variants.append(urllib.parse.quote(original_payload))
            
            # HTML entity encoding
            html_encoded = original_payload.replace('{', '&#123;').replace('}', '&#125;')
            variants.append(html_encoded)
            
            # Case variations
            variants.append(original_payload.upper())
            variants.append(original_payload.lower())
            
            # Whitespace variations
            variants.append(original_payload.replace(' ', '\t'))
            variants.append(original_payload.replace(' ', '\n'))
            variants.append(original_payload.replace(' ', ''))
        
        return list(set(variants))  # Remove duplicates
    
    def optimize_payload_order(self, 
                             payloads: List[str],
                             context: str = "",
                             target_url: str = "") -> List[str]:
        """
        Optimize payload order based on success probability.
        
        Args:
            payloads: List of payloads to optimize
            context: Injection context
            target_url: Target URL for historical analysis
            
        Returns:
            Optimized payload list
        """
        # Calculate success scores for each payload
        scored_payloads = []
        
        for payload in payloads:
            score = self._calculate_payload_score(payload, context, target_url)
            scored_payloads.append((payload, score))
        
        # Sort by score (highest first)
        scored_payloads.sort(key=lambda x: x[1], reverse=True)
        
        return [payload for payload, _ in scored_payloads]
    
    def _calculate_payload_score(self, 
                               payload: str,
                               context: str,
                               target_url: str) -> float:
        """Calculate success score for a payload."""
        base_score = 0.5
        
        # Historical success rate
        if target_url in self.success_history:
            successes = [r for r in self.success_history[target_url] 
                        if r.payload == payload and r.success]
            total_attempts = [r for r in self.success_history[target_url] 
                            if r.payload == payload]
            
            if total_attempts:
                historical_rate = len(successes) / len(total_attempts)
                base_score = historical_rate * 0.7 + base_score * 0.3
        
        # Context success rate
        if context and context in self.context_success_rates:
            context_rate = self.context_success_rates[context].get(payload, 0.5)
            base_score = context_rate * 0.5 + base_score * 0.5
        
        # Payload complexity penalty
        if len(payload) > 200:
            base_score *= 0.8
        elif len(payload) > 100:
            base_score *= 0.9
        
        # Simple payloads bonus
        if payload in ["{{7*7}}", "${7*7}", "{7*7}"]:
            base_score *= 1.2
        
        return min(1.0, base_score)
    
    def record_payload_result(self, 
                            target_url: str,
                            payload: str,
                            result: PayloadResult) -> None:
        """
        Record payload execution result for learning.
        
        Args:
            target_url: Target URL
            payload: Payload that was executed
            result: Execution result
        """
        if target_url not in self.success_history:
            self.success_history[target_url] = []
        
        self.success_history[target_url].append(result)
        
        # Update context success rates
        # This would need context information from the caller
        # For now, we'll update global success rates
        
    def get_targeted_payloads(self, 
                            detected_engine: str,
                            vulnerability_types: List[VulnerabilityType],
                            max_payloads: int = 50) -> List[str]:
        """
        Get targeted payloads for a detected engine and vulnerability types.
        
        Args:
            detected_engine: Name of detected template engine
            vulnerability_types: Types of vulnerabilities to target
            max_payloads: Maximum number of payloads to return
            
        Returns:
            List of targeted payloads
        """
        engine = EngineFactory.create_engine(detected_engine)
        if not engine:
            return []
        
        payloads = []
        for vuln_type in vulnerability_types:
            if vuln_type in engine.payloads:
                payloads.extend(engine.payloads[vuln_type])
        
        # Remove duplicates and limit
        unique_payloads = list(dict.fromkeys(payloads))
        return unique_payloads[:max_payloads]
    
    def generate_custom_payload(self, 
                              template: str,
                              engine_name: str,
                              parameters: Dict[str, str]) -> str:
        """
        Generate custom payload from template.
        
        Args:
            template: Payload template with placeholders
            engine_name: Target template engine
            parameters: Parameters to fill in template
            
        Returns:
            Generated payload
        """
        payload = template
        for key, value in parameters.items():
            placeholder = f"{{{key}}}"
            payload = payload.replace(placeholder, value)
        
        return payload
