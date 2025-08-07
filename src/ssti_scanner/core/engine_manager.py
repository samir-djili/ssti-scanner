"""
Engine Manager for SSTI Scanner.

This module provides centralized management of template engines, including
engine lifecycle, configuration, and coordination.
"""

import logging
from typing import List, Dict, Any, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
import asyncio

from ..engines.engine_factory import EngineFactory
from ..engines.base_template_engine import BaseTemplateEngine, TemplateEngine


class EngineManager:
    """
    Manages template engines and coordinates their execution.
    
    This class provides:
    1. Engine lifecycle management
    2. Parallel execution coordination
    3. Engine configuration and optimization
    4. Performance monitoring and statistics
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the engine manager.
        
        Args:
            config: Configuration dictionary for engine management
        """
        self.logger = logging.getLogger(__name__)
        self.config = config or {}
        self.engine_factory = EngineFactory()
        self.engines = {}
        self.engine_stats = {}
        self.active_engines = set()
        
        # Load engines
        self._initialize_engines()
        
    def _initialize_engines(self):
        """Initialize all available template engines."""
        try:
            all_engines = self.engine_factory.create_all_engines()
            
            for engine in all_engines:
                self.engines[engine.name] = engine
                self.engine_stats[engine.name] = {
                    'tests_run': 0,
                    'vulnerabilities_found': 0,
                    'false_positives': 0,
                    'execution_time': 0.0,
                    'success_rate': 0.0
                }
                
            self.logger.info(f"Initialized {len(self.engines)} template engines")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize engines: {e}")
            
    def get_engine(self, engine_name: str) -> Optional[BaseTemplateEngine]:
        """
        Get a specific template engine by name.
        
        Args:
            engine_name: Name of the engine to retrieve
            
        Returns:
            Template engine instance or None if not found
        """
        return self.engines.get(engine_name)
    
    def get_all_engines(self) -> List[BaseTemplateEngine]:
        """
        Get all available template engines.
        
        Returns:
            List of all template engine instances
        """
        return list(self.engines.values())
    
    def get_engines_by_category(self, category: str) -> List[BaseTemplateEngine]:
        """
        Get engines filtered by category/type.
        
        Args:
            category: Engine category ('python', 'java', 'php', etc.)
            
        Returns:
            List of engines in the specified category
        """
        category_mapping = {
            'python': ['jinja2', 'django', 'mako'],
            'java': ['freemarker', 'velocity', 'thymeleaf'],
            'php': ['twig', 'smarty'],
            'javascript': ['handlebars', 'mustache'],
            'ruby': ['erb', 'haml']
        }
        
        engine_names = category_mapping.get(category.lower(), [])
        return [self.engines[name] for name in engine_names if name in self.engines]
    
    def get_high_confidence_engines(self) -> List[BaseTemplateEngine]:
        """
        Get engines with high success rates for priority testing.
        
        Returns:
            List of engines sorted by success rate
        """
        sorted_engines = sorted(
            self.engines.values(),
            key=lambda e: self.engine_stats[e.name]['success_rate'],
            reverse=True
        )
        
        # Return top performers or all if success rates are not established
        threshold = 0.7
        high_confidence = [
            engine for engine in sorted_engines
            if self.engine_stats[engine.name]['success_rate'] >= threshold
        ]
        
        return high_confidence if high_confidence else sorted_engines[:3]
    
    async def test_engines_parallel(self, url: str, param_name: str, 
                                  test_value: str, engine_names: Optional[List[str]] = None,
                                  max_concurrent: int = 5) -> Dict[str, Any]:
        """
        Test multiple engines in parallel for better performance.
        
        Args:
            url: Target URL
            param_name: Parameter name to test
            test_value: Value to test with
            engine_names: Specific engines to test (optional)
            max_concurrent: Maximum concurrent engine tests
            
        Returns:
            Dictionary of results from all engines
        """
        engines_to_test = []
        
        if engine_names:
            engines_to_test = [
                self.engines[name] for name in engine_names 
                if name in self.engines
            ]
        else:
            engines_to_test = list(self.engines.values())
            
        if not engines_to_test:
            return {}
            
        # Limit concurrent executions
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def test_single_engine(engine):
            async with semaphore:
                return await self._test_engine_async(engine, url, param_name, test_value)
                
        # Execute tests concurrently
        tasks = [test_single_engine(engine) for engine in engines_to_test]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Compile results
        compiled_results = {}
        for engine, result in zip(engines_to_test, results):
            if isinstance(result, Exception):
                self.logger.error(f"Engine {engine.name} failed: {result}")
                compiled_results[engine.name] = {
                    'success': False,
                    'error': str(result)
                }
            else:
                compiled_results[engine.name] = result
                
        return compiled_results
    
    async def _test_engine_async(self, engine: BaseTemplateEngine, 
                               url: str, param_name: str, test_value: str) -> Dict[str, Any]:
        """
        Test a single engine asynchronously.
        
        Args:
            engine: Template engine to test
            url: Target URL
            param_name: Parameter name
            test_value: Test value
            
        Returns:
            Test results for the engine
        """
        import time
        start_time = time.time()
        
        try:
            # Mark engine as active
            self.active_engines.add(engine.name)
            
            # Get test payload
            payload_info = engine.get_basic_payload()
            if not payload_info:
                return {'success': False, 'error': 'No basic payload available'}
                
            # This would integrate with actual HTTP testing
            # For now, simulate the test
            execution_time = time.time() - start_time
            
            # Update statistics
            self.engine_stats[engine.name]['tests_run'] += 1
            self.engine_stats[engine.name]['execution_time'] += execution_time
            
            return {
                'success': True,
                'engine': engine.name,
                'execution_time': execution_time,
                'payload_used': payload_info
            }
            
        except Exception as e:
            self.logger.error(f"Engine {engine.name} test failed: {e}")
            return {
                'success': False,
                'engine': engine.name,
                'error': str(e)
            }
        finally:
            # Mark engine as inactive
            self.active_engines.discard(engine.name)
            
    def prioritize_engines(self, context: Dict[str, Any]) -> List[BaseTemplateEngine]:
        """
        Prioritize engines based on context clues and statistics.
        
        Args:
            context: Context information (URL, headers, detected technologies, etc.)
            
        Returns:
            List of engines in priority order
        """
        prioritized = []
        
        # Check for technology-specific indicators
        url = context.get('url', '').lower()
        headers = context.get('headers', {})
        detected_tech = context.get('technologies', [])
        
        # Technology-based prioritization
        if any(tech in detected_tech for tech in ['django', 'python']):
            prioritized.extend(self.get_engines_by_category('python'))
        elif any(tech in detected_tech for tech in ['spring', 'java']):
            prioritized.extend(self.get_engines_by_category('java'))
        elif any(tech in detected_tech for tech in ['php', 'symfony']):
            prioritized.extend(self.get_engines_by_category('php'))
        elif any(tech in detected_tech for tech in ['node', 'express']):
            prioritized.extend(self.get_engines_by_category('javascript'))
        elif any(tech in detected_tech for tech in ['rails', 'ruby']):
            prioritized.extend(self.get_engines_by_category('ruby'))
            
        # URL-based hints
        if '.php' in url:
            prioritized.extend(self.get_engines_by_category('php'))
        elif '.jsp' in url or '.do' in url:
            prioritized.extend(self.get_engines_by_category('java'))
        elif '.py' in url or 'django' in url:
            prioritized.extend(self.get_engines_by_category('python'))
            
        # Add high-confidence engines
        prioritized.extend(self.get_high_confidence_engines())
        
        # Add remaining engines
        all_engines = set(self.engines.values())
        remaining = all_engines - set(prioritized)
        prioritized.extend(list(remaining))
        
        # Remove duplicates while preserving order
        seen = set()
        result = []
        for engine in prioritized:
            if engine.name not in seen:
                seen.add(engine.name)
                result.append(engine)
                
        return result
    
    def get_engine_statistics(self) -> Dict[str, Dict[str, Any]]:
        """
        Get performance statistics for all engines.
        
        Returns:
            Dictionary of engine statistics
        """
        stats = {}
        
        for engine_name, engine_stats in self.engine_stats.items():
            tests_run = engine_stats['tests_run']
            
            stats[engine_name] = {
                'tests_run': tests_run,
                'vulnerabilities_found': engine_stats['vulnerabilities_found'],
                'false_positives': engine_stats['false_positives'],
                'average_execution_time': (
                    engine_stats['execution_time'] / tests_run if tests_run > 0 else 0
                ),
                'success_rate': engine_stats['success_rate'],
                'is_active': engine_name in self.active_engines
            }
            
        return stats
    
    def update_engine_stats(self, engine_name: str, vulnerability_found: bool,
                          false_positive: bool = False, execution_time: float = 0.0):
        """
        Update statistics for an engine after a test.
        
        Args:
            engine_name: Name of the engine
            vulnerability_found: Whether a vulnerability was found
            false_positive: Whether the result was a false positive
            execution_time: Time taken for the test
        """
        if engine_name not in self.engine_stats:
            return
            
        stats = self.engine_stats[engine_name]
        
        if vulnerability_found:
            stats['vulnerabilities_found'] += 1
            
        if false_positive:
            stats['false_positives'] += 1
            
        stats['execution_time'] += execution_time
        
        # Calculate success rate (vulnerabilities found - false positives / total tests)
        if stats['tests_run'] > 0:
            successful_detections = stats['vulnerabilities_found'] - stats['false_positives']
            stats['success_rate'] = successful_detections / stats['tests_run']
            
    def reset_statistics(self):
        """Reset all engine statistics."""
        for engine_name in self.engine_stats:
            self.engine_stats[engine_name] = {
                'tests_run': 0,
                'vulnerabilities_found': 0,
                'false_positives': 0,
                'execution_time': 0.0,
                'success_rate': 0.0
            }
            
        self.logger.info("Engine statistics reset")
    
    def get_active_engines(self) -> Set[str]:
        """
        Get currently active/running engines.
        
        Returns:
            Set of active engine names
        """
        return self.active_engines.copy()
    
    def stop_all_engines(self):
        """Stop all active engines and cleanup."""
        self.active_engines.clear()
        self.logger.info("All engines stopped")
    
    def reload_engines(self):
        """Reload all engines from the factory."""
        self.stop_all_engines()
        self.engines.clear()
        self._initialize_engines()
        self.logger.info("Engines reloaded")
        
    def get_engine_recommendations(self, target_info: Dict[str, Any]) -> List[str]:
        """
        Get recommended engines based on target information.
        
        Args:
            target_info: Information about the target (technology, response patterns, etc.)
            
        Returns:
            List of recommended engine names in priority order
        """
        recommendations = []
        
        # Analyze target information
        server_header = target_info.get('server', '').lower()
        technologies = target_info.get('technologies', [])
        response_patterns = target_info.get('response_patterns', [])
        
        # Server-based recommendations
        if 'apache' in server_header and 'php' in server_header:
            recommendations.extend(['twig', 'smarty'])
        elif 'nginx' in server_header:
            recommendations.extend(['jinja2', 'handlebars'])
        elif 'tomcat' in server_header or 'jetty' in server_header:
            recommendations.extend(['freemarker', 'velocity', 'thymeleaf'])
            
        # Technology-based recommendations
        for tech in technologies:
            if tech.lower() in ['symfony', 'drupal']:
                recommendations.append('twig')
            elif tech.lower() in ['flask', 'django']:
                recommendations.extend(['jinja2', 'django'])
            elif tech.lower() in ['spring', 'struts']:
                recommendations.extend(['freemarker', 'velocity'])
                
        # Response pattern analysis
        for pattern in response_patterns:
            if '{{' in pattern and '}}' in pattern:
                recommendations.extend(['jinja2', 'handlebars', 'twig'])
            elif '{%' in pattern and '%}' in pattern:
                recommendations.extend(['jinja2', 'twig', 'django'])
            elif '${' in pattern and '}' in pattern:
                recommendations.extend(['freemarker', 'velocity'])
                
        # Remove duplicates while preserving order
        seen = set()
        unique_recommendations = []
        for engine_name in recommendations:
            if engine_name not in seen and engine_name in self.engines:
                seen.add(engine_name)
                unique_recommendations.append(engine_name)
                
        # Add remaining engines if less than 3 recommendations
        if len(unique_recommendations) < 3:
            high_confidence = self.get_high_confidence_engines()
            for engine in high_confidence:
                if engine.name not in seen:
                    unique_recommendations.append(engine.name)
                    if len(unique_recommendations) >= 5:
                        break
                        
        return unique_recommendations
