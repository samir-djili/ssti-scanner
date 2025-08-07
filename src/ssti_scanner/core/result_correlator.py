"""
Result Correlator for SSTI Scanner.

This module provides correlation and validation of SSTI vulnerability findings
to reduce false positives and improve detection accuracy.
"""

import logging
import re
import hashlib
from typing import List, Dict, Any, Optional, Set, Tuple
from collections import defaultdict, Counter
from datetime import datetime
import json


class ResultCorrelator:
    """
    Correlates and validates SSTI vulnerability findings across multiple tests.
    
    This class provides:
    1. False positive reduction through cross-validation
    2. Confidence scoring based on multiple indicators
    3. Result deduplication and consolidation
    4. Evidence correlation and ranking
    """
    
    def __init__(self):
        """Initialize the result correlator."""
        self.logger = logging.getLogger(__name__)
        self.raw_results = []
        self.correlated_results = []
        self.false_positive_patterns = self._load_false_positive_patterns()
        
    def add_result(self, result: Dict[str, Any]):
        """
        Add a raw vulnerability result for correlation.
        
        Args:
            result: Raw vulnerability result from detection engine
        """
        if self._is_valid_result(result):
            result['timestamp'] = datetime.now().isoformat()
            result['result_id'] = self._generate_result_id(result)
            self.raw_results.append(result)
            self.logger.debug(f"Added result {result['result_id']} for correlation")
        else:
            self.logger.warning("Invalid result format, skipping")
    
    def correlate_results(self) -> List[Dict[str, Any]]:
        """
        Correlate all added results and return validated findings.
        
        Returns:
            List of correlated and validated vulnerability findings
        """
        if not self.raw_results:
            return []
            
        # Group results by target (URL + parameter)
        grouped_results = self._group_results_by_target()
        
        # Correlate each group
        correlated = []
        for target_key, target_results in grouped_results.items():
            target_correlation = self._correlate_target_results(target_key, target_results)
            if target_correlation:
                correlated.append(target_correlation)
                
        # Sort by confidence and risk
        correlated.sort(key=lambda x: (x['final_confidence'], x['risk_score']), reverse=True)
        
        self.correlated_results = correlated
        self.logger.info(f"Correlated {len(self.raw_results)} raw results into {len(correlated)} findings")
        
        return correlated
    
    def _group_results_by_target(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Group results by target (URL + parameter combination).
        
        Returns:
            Dictionary with target keys and their associated results
        """
        grouped = defaultdict(list)
        
        for result in self.raw_results:
            target_key = self._generate_target_key(result)
            grouped[target_key].append(result)
            
        return dict(grouped)
    
    def _generate_target_key(self, result: Dict[str, Any]) -> str:
        """
        Generate a unique key for a target (URL + parameter).
        
        Args:
            result: Vulnerability result
            
        Returns:
            Target key string
        """
        url = result.get('url', '')
        parameter = result.get('parameter', '')
        return f"{url}#{parameter}"
    
    def _correlate_target_results(self, target_key: str, 
                                results: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Correlate results for a specific target.
        
        Args:
            target_key: Target identifier
            results: List of results for this target
            
        Returns:
            Correlated result or None if no valid vulnerability found
        """
        if not results:
            return None
            
        # Analyze detection patterns
        engine_detections = self._analyze_engine_detections(results)
        
        # Calculate confidence scores
        confidence_analysis = self._calculate_confidence_scores(results, engine_detections)
        
        # Check for false positives
        false_positive_analysis = self._check_false_positives(results)
        
        # Validate with cross-engine correlation
        cross_validation = self._cross_validate_engines(results)
        
        # Calculate final confidence
        final_confidence = self._calculate_final_confidence(
            confidence_analysis, false_positive_analysis, cross_validation
        )
        
        # Filter out low-confidence results
        if final_confidence < 0.3:
            self.logger.debug(f"Filtering out low-confidence result for {target_key}")
            return None
            
        # Build correlated result
        best_result = max(results, key=lambda r: r.get('confidence', 0))
        
        correlated_result = {
            'target_key': target_key,
            'url': best_result.get('url'),
            'parameter': best_result.get('parameter'),
            'vulnerability_type': 'SSTI',
            'final_confidence': final_confidence,
            'risk_score': self._calculate_risk_score(results, final_confidence),
            'detected_engines': list(engine_detections.keys()),
            'total_detections': len(results),
            'evidence': self._compile_evidence(results),
            'payloads_tested': len(set(r.get('payload', '') for r in results)),
            'unique_responses': len(set(r.get('response_content', '')[:500] for r in results)),
            'first_detected': min(r.get('timestamp', '') for r in results),
            'last_detected': max(r.get('timestamp', '') for r in results),
            'analysis': {
                'engine_detections': engine_detections,
                'confidence_breakdown': confidence_analysis,
                'false_positive_indicators': false_positive_analysis,
                'cross_validation': cross_validation
            },
            'recommendations': self._generate_recommendations(results, final_confidence),
            'raw_results': results
        }
        
        return correlated_result
    
    def _analyze_engine_detections(self, results: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """
        Analyze detections by template engine.
        
        Args:
            results: List of vulnerability results
            
        Returns:
            Analysis of detections by engine
        """
        engine_analysis = defaultdict(lambda: {
            'detections': 0,
            'confidence_scores': [],
            'payloads': [],
            'unique_responses': set()
        })
        
        for result in results:
            engine = result.get('engine', 'unknown')
            confidence = result.get('confidence', 0)
            payload = result.get('payload', '')
            response = result.get('response_content', '')[:200]
            
            engine_analysis[engine]['detections'] += 1
            engine_analysis[engine]['confidence_scores'].append(confidence)
            engine_analysis[engine]['payloads'].append(payload)
            engine_analysis[engine]['unique_responses'].add(response)
            
        # Calculate average confidence per engine
        for engine, data in engine_analysis.items():
            scores = data['confidence_scores']
            data['average_confidence'] = sum(scores) / len(scores) if scores else 0
            data['max_confidence'] = max(scores) if scores else 0
            data['unique_responses'] = len(data['unique_responses'])
            
        return dict(engine_analysis)
    
    def _calculate_confidence_scores(self, results: List[Dict[str, Any]], 
                                   engine_detections: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculate confidence scores based on various factors.
        
        Args:
            results: List of vulnerability results
            engine_detections: Engine detection analysis
            
        Returns:
            Confidence analysis breakdown
        """
        analysis = {
            'base_confidence': 0,
            'engine_diversity_bonus': 0,
            'response_consistency_bonus': 0,
            'payload_diversity_bonus': 0,
            'timing_consistency_bonus': 0
        }
        
        if not results:
            return analysis
            
        # Base confidence from individual results
        confidences = [r.get('confidence', 0) for r in results]
        analysis['base_confidence'] = max(confidences) if confidences else 0
        
        # Engine diversity bonus (multiple engines detecting = higher confidence)
        unique_engines = len(engine_detections)
        if unique_engines >= 3:
            analysis['engine_diversity_bonus'] = 0.2
        elif unique_engines >= 2:
            analysis['engine_diversity_bonus'] = 0.1
            
        # Response consistency bonus
        response_patterns = self._analyze_response_patterns(results)
        if response_patterns['consistent_evaluation']:
            analysis['response_consistency_bonus'] = 0.15
        elif response_patterns['partial_consistency']:
            analysis['response_consistency_bonus'] = 0.05
            
        # Payload diversity bonus (different payloads giving similar results)
        unique_payloads = len(set(r.get('payload', '') for r in results))
        if unique_payloads >= 3:
            analysis['payload_diversity_bonus'] = 0.1
        elif unique_payloads >= 2:
            analysis['payload_diversity_bonus'] = 0.05
            
        return analysis
    
    def _analyze_response_patterns(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze response patterns for consistency.
        
        Args:
            results: List of vulnerability results
            
        Returns:
            Response pattern analysis
        """
        analysis = {
            'consistent_evaluation': False,
            'partial_consistency': False,
            'math_expressions_evaluated': 0,
            'object_disclosures': 0,
            'error_patterns': 0
        }
        
        math_results = []
        error_patterns = []
        object_disclosures = []
        
        for result in results:
            payload = result.get('payload', '')
            response = result.get('response_content', '')
            expected = result.get('expected_output', '')
            
            # Check for mathematical evaluation
            if self._contains_math_evaluation(payload, response, expected):
                analysis['math_expressions_evaluated'] += 1
                math_results.append((payload, response, expected))
                
            # Check for object disclosure
            if self._contains_object_disclosure(response):
                analysis['object_disclosures'] += 1
                object_disclosures.append(response)
                
            # Check for template error patterns
            if self._contains_template_errors(response):
                analysis['error_patterns'] += 1
                error_patterns.append(response)
                
        # Determine consistency levels
        total_results = len(results)
        if analysis['math_expressions_evaluated'] >= max(2, total_results * 0.6):
            analysis['consistent_evaluation'] = True
        elif analysis['math_expressions_evaluated'] >= 1:
            analysis['partial_consistency'] = True
            
        return analysis
    
    def _check_false_positives(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Check for false positive indicators.
        
        Args:
            results: List of vulnerability results
            
        Returns:
            False positive analysis
        """
        analysis = {
            'false_positive_score': 0,
            'indicators': [],
            'static_responses': 0,
            'error_only_responses': 0,
            'reflection_without_evaluation': 0
        }
        
        for result in results:
            payload = result.get('payload', '')
            response = result.get('response_content', '')
            baseline = result.get('baseline_content', '')
            
            # Check for static responses (payload appears unchanged)
            if payload in response and not self._has_evaluation_evidence(payload, response):
                analysis['static_responses'] += 1
                analysis['indicators'].append('payload_reflection_without_evaluation')
                
            # Check for error-only responses
            if self._is_error_only_response(response):
                analysis['error_only_responses'] += 1
                analysis['indicators'].append('error_only_response')
                
            # Check against known false positive patterns
            for pattern in self.false_positive_patterns:
                if re.search(pattern, response, re.IGNORECASE):
                    analysis['false_positive_score'] += 0.1
                    analysis['indicators'].append(f'fp_pattern_match: {pattern[:30]}')
                    
        # Calculate overall false positive score
        total_results = len(results)
        if total_results > 0:
            static_ratio = analysis['static_responses'] / total_results
            error_ratio = analysis['error_only_responses'] / total_results
            
            analysis['false_positive_score'] += static_ratio * 0.3 + error_ratio * 0.2
            
        return analysis
    
    def _cross_validate_engines(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Cross-validate results across different template engines.
        
        Args:
            results: List of vulnerability results
            
        Returns:
            Cross-validation analysis
        """
        validation = {
            'engines_agreeing': 0,
            'consistent_detections': False,
            'conflicting_engines': [],
            'validation_score': 0
        }
        
        engine_results = defaultdict(list)
        
        # Group by engine
        for result in results:
            engine = result.get('engine', 'unknown')
            confidence = result.get('confidence', 0)
            engine_results[engine].append(confidence)
            
        # Count engines with high-confidence detections
        high_confidence_engines = 0
        for engine, confidences in engine_results.items():
            max_confidence = max(confidences) if confidences else 0
            if max_confidence >= 0.7:
                high_confidence_engines += 1
                
        validation['engines_agreeing'] = high_confidence_engines
        
        # Check for consistency
        if high_confidence_engines >= 2:
            validation['consistent_detections'] = True
            validation['validation_score'] = min(high_confidence_engines * 0.2, 0.8)
        elif high_confidence_engines >= 1:
            validation['validation_score'] = 0.1
            
        return validation
    
    def _calculate_final_confidence(self, confidence_analysis: Dict[str, Any],
                                  false_positive_analysis: Dict[str, Any],
                                  cross_validation: Dict[str, Any]) -> float:
        """
        Calculate final confidence score.
        
        Args:
            confidence_analysis: Confidence analysis breakdown
            false_positive_analysis: False positive indicators
            cross_validation: Cross-validation results
            
        Returns:
            Final confidence score (0.0 to 1.0)
        """
        # Start with base confidence
        confidence = confidence_analysis['base_confidence']
        
        # Add bonuses
        confidence += confidence_analysis['engine_diversity_bonus']
        confidence += confidence_analysis['response_consistency_bonus']
        confidence += confidence_analysis['payload_diversity_bonus']
        confidence += cross_validation['validation_score']
        
        # Apply false positive penalty
        fp_penalty = false_positive_analysis['false_positive_score']
        confidence -= fp_penalty
        
        # Ensure confidence is within bounds
        return max(0.0, min(1.0, confidence))
    
    def _calculate_risk_score(self, results: List[Dict[str, Any]], confidence: float) -> float:
        """
        Calculate risk score based on vulnerability characteristics.
        
        Args:
            results: List of vulnerability results
            confidence: Final confidence score
            
        Returns:
            Risk score (0.0 to 10.0)
        """
        base_risk = confidence * 7.0  # Base risk from confidence
        
        # Risk modifiers
        risk_modifiers = 0
        
        # Check for code execution evidence
        for result in results:
            response = result.get('response_content', '')
            
            # Object disclosure increases risk
            if self._contains_object_disclosure(response):
                risk_modifiers += 1.0
                
            # Mathematical evaluation increases risk
            if self._contains_math_evaluation(
                result.get('payload', ''), response, result.get('expected_output', '')
            ):
                risk_modifiers += 1.5
                
            # System information disclosure
            if self._contains_system_info(response):
                risk_modifiers += 2.0
                
        return min(10.0, base_risk + risk_modifiers)
    
    def _compile_evidence(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Compile evidence from all results.
        
        Args:
            results: List of vulnerability results
            
        Returns:
            List of evidence items
        """
        evidence = []
        
        for result in results:
            engine = result.get('engine', 'unknown')
            payload = result.get('payload', '')
            response = result.get('response_content', '')
            confidence = result.get('confidence', 0)
            
            evidence_item = {
                'engine': engine,
                'payload': payload,
                'response_snippet': response[:200] if response else '',
                'confidence': confidence,
                'evidence_type': self._classify_evidence(payload, response),
                'timestamp': result.get('timestamp', '')
            }
            
            evidence.append(evidence_item)
            
        # Sort by confidence
        evidence.sort(key=lambda x: x['confidence'], reverse=True)
        
        return evidence[:10]  # Limit to top 10 pieces of evidence
    
    def _classify_evidence(self, payload: str, response: str) -> str:
        """
        Classify the type of evidence.
        
        Args:
            payload: Test payload
            response: Server response
            
        Returns:
            Evidence type classification
        """
        if self._contains_math_evaluation(payload, response, ''):
            return 'mathematical_evaluation'
        elif self._contains_object_disclosure(response):
            return 'object_disclosure'
        elif self._contains_template_errors(response):
            return 'template_error'
        elif self._contains_system_info(response):
            return 'system_information'
        elif payload in response:
            return 'payload_reflection'
        else:
            return 'behavioral_change'
    
    def _generate_recommendations(self, results: List[Dict[str, Any]], 
                                confidence: float) -> List[str]:
        """
        Generate recommendations based on analysis.
        
        Args:
            results: List of vulnerability results
            confidence: Final confidence score
            
        Returns:
            List of recommendations
        """
        recommendations = []
        
        if confidence >= 0.8:
            recommendations.append("High confidence SSTI vulnerability detected. Immediate remediation required.")
        elif confidence >= 0.6:
            recommendations.append("Likely SSTI vulnerability. Manual verification recommended.")
        else:
            recommendations.append("Possible SSTI vulnerability. Further investigation needed.")
            
        # Engine-specific recommendations
        engines = set(r.get('engine', '') for r in results)
        if 'jinja2' in engines or 'django' in engines:
            recommendations.append("Consider implementing autoescaping and input validation for Python templates.")
        if 'twig' in engines:
            recommendations.append("Review Twig template security settings and disable dangerous functions.")
        if 'freemarker' in engines or 'velocity' in engines:
            recommendations.append("Restrict template function access and validate user input in Java templates.")
            
        # General recommendations
        recommendations.append("Implement input validation and output encoding.")
        recommendations.append("Use sandboxed template environments when possible.")
        recommendations.append("Avoid user-controlled template content.")
        
        return recommendations
    
    def _contains_math_evaluation(self, payload: str, response: str, expected: str) -> bool:
        """Check if response contains mathematical evaluation."""
        # Look for calculated results in response
        math_patterns = [
            r'\b(49|7)\b',  # 7*7=49
            r'\b(14|2)\b',  # 7*2=14 or similar
            r'\b(144|12)\b',  # 12*12=144
            r'\b(15|3)\b'   # 5*3=15
        ]
        
        for pattern in math_patterns:
            if re.search(pattern, response) and pattern not in payload:
                return True
                
        return False
    
    def _contains_object_disclosure(self, response: str) -> bool:
        """Check if response contains object/class disclosure."""
        disclosure_patterns = [
            r'<class\s+[\'"][^\'\"]+[\'"]>',
            r'<built-in\s+method\s+[^>]+>',
            r'<module\s+[\'"][^\'\"]+[\'"]>',
            r'java\.lang\.',
            r'__class__',
            r'__bases__',
            r'getClass\(\)'
        ]
        
        for pattern in disclosure_patterns:
            if re.search(pattern, response, re.IGNORECASE):
                return True
                
        return False
    
    def _contains_template_errors(self, response: str) -> bool:
        """Check if response contains template engine errors."""
        error_patterns = [
            r'TemplateException',
            r'UndefinedError',
            r'SyntaxError.*template',
            r'ParseException',
            r'TemplateSyntaxError'
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, response, re.IGNORECASE):
                return True
                
        return False
    
    def _contains_system_info(self, response: str) -> bool:
        """Check if response contains system information."""
        system_patterns = [
            r'/etc/passwd',
            r'C:\\Windows',
            r'java\.version',
            r'os\.name',
            r'user\.home'
        ]
        
        for pattern in system_patterns:
            if re.search(pattern, response, re.IGNORECASE):
                return True
                
        return False
    
    def _has_evaluation_evidence(self, payload: str, response: str) -> bool:
        """Check if there's evidence of payload evaluation."""
        return (self._contains_math_evaluation(payload, response, '') or
                self._contains_object_disclosure(response) or
                self._contains_system_info(response))
    
    def _is_error_only_response(self, response: str) -> bool:
        """Check if response contains only errors."""
        error_indicators = ['error', 'exception', 'warning', 'failed', 'invalid']
        response_lower = response.lower()
        
        has_errors = any(indicator in response_lower for indicator in error_indicators)
        has_content = len(response.strip()) > 100
        
        return has_errors and not has_content
    
    def _load_false_positive_patterns(self) -> List[str]:
        """Load patterns that commonly indicate false positives."""
        return [
            r'404\s+not\s+found',
            r'access\s+denied',
            r'permission\s+denied',
            r'file\s+not\s+found',
            r'invalid\s+request',
            r'bad\s+request',
            r'method\s+not\s+allowed',
            r'internal\s+server\s+error',
            r'service\s+unavailable'
        ]
    
    def _is_valid_result(self, result: Dict[str, Any]) -> bool:
        """Validate result format."""
        required_fields = ['url', 'parameter', 'engine', 'payload', 'confidence']
        return all(field in result for field in required_fields)
    
    def _generate_result_id(self, result: Dict[str, Any]) -> str:
        """Generate unique ID for a result."""
        key_data = f"{result.get('url', '')}{result.get('parameter', '')}{result.get('payload', '')}"
        return hashlib.md5(key_data.encode()).hexdigest()[:12]
    
    def get_summary_statistics(self) -> Dict[str, Any]:
        """Get summary statistics of correlation results."""
        if not self.correlated_results:
            return {}
            
        confidences = [r['final_confidence'] for r in self.correlated_results]
        risks = [r['risk_score'] for r in self.correlated_results]
        
        return {
            'total_vulnerabilities': len(self.correlated_results),
            'high_confidence_count': len([c for c in confidences if c >= 0.8]),
            'medium_confidence_count': len([c for c in confidences if 0.5 <= c < 0.8]),
            'low_confidence_count': len([c for c in confidences if c < 0.5]),
            'average_confidence': sum(confidences) / len(confidences),
            'average_risk_score': sum(risks) / len(risks),
            'engines_used': len(set(
                engine for result in self.correlated_results 
                for engine in result['detected_engines']
            )),
            'total_raw_results': len(self.raw_results)
        }
    
    def reset(self):
        """Reset the correlator state."""
        self.raw_results.clear()
        self.correlated_results.clear()
        self.logger.info("Result correlator reset")
