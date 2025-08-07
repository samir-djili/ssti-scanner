"""
Unit tests for template engines.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.engines.base import BaseTemplateEngine, EngineResult, ConfidenceLevel
from src.engines.jinja2_engine import Jinja2Engine
from src.core.config import ScanConfig


class TestBaseTemplateEngine:
    """Test base template engine functionality."""
    
    def test_base_engine_initialization(self):
        """Test base engine initialization."""
        config = ScanConfig()
        engine = BaseTemplateEngine(config)
        
        assert engine.config == config
        assert engine.name == "base"
        assert len(engine.payloads) == 0
    
    def test_engine_result_creation(self):
        """Test engine result creation."""
        result = EngineResult(
            is_vulnerable=True,
            confidence=ConfidenceLevel.HIGH,
            payload="{{7*7}}",
            response="49",
            evidence="Mathematical operation executed",
            engine="jinja2"
        )
        
        assert result.is_vulnerable is True
        assert result.confidence == ConfidenceLevel.HIGH
        assert result.payload == "{{7*7}}"
        assert result.response == "49"
        assert result.evidence == "Mathematical operation executed"
        assert result.engine == "jinja2"
    
    def test_confidence_level_enum(self):
        """Test confidence level enumeration."""
        assert ConfidenceLevel.LOW.value == "low"
        assert ConfidenceLevel.MEDIUM.value == "medium"
        assert ConfidenceLevel.HIGH.value == "high"
        
        # Test ordering
        assert ConfidenceLevel.LOW < ConfidenceLevel.MEDIUM
        assert ConfidenceLevel.MEDIUM < ConfidenceLevel.HIGH
    
    def test_abstract_methods(self):
        """Test that abstract methods raise NotImplementedError."""
        config = ScanConfig()
        engine = BaseTemplateEngine(config)
        
        with pytest.raises(NotImplementedError):
            asyncio.run(engine.test_payload("test", "{{test}}"))
        
        with pytest.raises(NotImplementedError):
            engine.analyze_response("test", "{{test}}", "response")


class TestJinja2Engine:
    """Test Jinja2 template engine."""
    
    @pytest.fixture
    def config(self):
        """Create test configuration."""
        return ScanConfig()
    
    @pytest.fixture
    def engine(self, config):
        """Create Jinja2 engine instance."""
        return Jinja2Engine(config)
    
    @pytest.fixture
    def mock_http_client(self):
        """Create mock HTTP client."""
        client = AsyncMock()
        return client
    
    def test_jinja2_engine_initialization(self, engine):
        """Test Jinja2 engine initialization."""
        assert engine.name == "jinja2"
        assert len(engine.payloads) > 0
        assert "{{7*7}}" in [p.payload for p in engine.payloads]
        assert "{{config}}" in [p.payload for p in engine.payloads]
    
    def test_payload_categories(self, engine):
        """Test payload categorization."""
        # Should have different payload types
        payload_types = set(p.type for p in engine.payloads)
        
        assert "math" in payload_types
        assert "config_access" in payload_types
        assert "code_execution" in payload_types
    
    def test_payload_contexts(self, engine):
        """Test payload contexts."""
        # Should have payloads for different contexts
        contexts = set(p.context for p in engine.payloads)
        
        assert "html" in contexts
        assert "url" in contexts
        assert "attribute" in contexts
    
    @pytest.mark.asyncio
    async def test_basic_math_detection(self, engine, mock_http_client):
        """Test basic mathematical operation detection."""
        url = "http://example.com/search?q=test"
        payload = "{{7*7}}"
        
        # Mock response showing executed math
        mock_http_client.get.return_value = {
            'status': 200,
            'text': "Search results for: 49",
            'headers': {'Content-Type': 'text/html'}
        }
        
        result = await engine.test_payload(url, payload, http_client=mock_http_client)
        
        assert result.is_vulnerable is True
        assert result.confidence in [ConfidenceLevel.HIGH, ConfidenceLevel.MEDIUM]
        assert result.payload == payload
        assert "49" in result.response
        assert result.engine == "jinja2"
    
    @pytest.mark.asyncio
    async def test_config_access_detection(self, engine, mock_http_client):
        """Test configuration object access detection."""
        url = "http://example.com/search?q=test"
        payload = "{{config}}"
        
        # Mock response showing config object
        mock_http_client.get.return_value = {
            'status': 200,
            'text': "Search results for: <Config 'production'>",
            'headers': {'Content-Type': 'text/html'}
        }
        
        result = await engine.test_payload(url, payload, http_client=mock_http_client)
        
        assert result.is_vulnerable is True
        assert result.confidence == ConfidenceLevel.HIGH
        assert "config" in result.evidence.lower()
    
    @pytest.mark.asyncio
    async def test_request_object_detection(self, engine, mock_http_client):
        """Test request object access detection."""
        url = "http://example.com/search?q=test"
        payload = "{{request}}"
        
        # Mock response showing request object
        mock_http_client.get.return_value = {
            'status': 200,
            'text': "Search results for: <Request 'http://example.com/search?q=test'>",
            'headers': {'Content-Type': 'text/html'}
        }
        
        result = await engine.test_payload(url, payload, http_client=mock_http_client)
        
        assert result.is_vulnerable is True
        assert result.confidence == ConfidenceLevel.HIGH
        assert "request" in result.evidence.lower()
    
    @pytest.mark.asyncio
    async def test_code_execution_detection(self, engine, mock_http_client):
        """Test code execution detection."""
        url = "http://example.com/search?q=test"
        payload = "{{''.__class__.__mro__[2].__subclasses__()}}"
        
        # Mock response showing class introspection
        mock_http_client.get.return_value = {
            'status': 200,
            'text': "Search results for: [<class 'type'>, <class 'weakref'>",
            'headers': {'Content-Type': 'text/html'}
        }
        
        result = await engine.test_payload(url, payload, http_client=mock_http_client)
        
        assert result.is_vulnerable is True
        assert result.confidence == ConfidenceLevel.HIGH
        assert "class" in result.evidence.lower()
    
    @pytest.mark.asyncio
    async def test_false_positive_avoidance(self, engine, mock_http_client):
        """Test avoiding false positives."""
        url = "http://example.com/search?q=test"
        payload = "{{7*7}}"
        
        # Mock response that just echoes the payload (not vulnerable)
        mock_http_client.get.return_value = {
            'status': 200,
            'text': "Search results for: {{7*7}}",
            'headers': {'Content-Type': 'text/html'}
        }
        
        result = await engine.test_payload(url, payload, http_client=mock_http_client)
        
        assert result.is_vulnerable is False
        assert result.confidence == ConfidenceLevel.LOW
    
    @pytest.mark.asyncio
    async def test_context_specific_payloads(self, engine, mock_http_client):
        """Test context-specific payload selection."""
        url = "http://example.com/search?q=test"
        
        # Test HTML context
        html_payloads = engine.get_payloads_for_context("html")
        assert len(html_payloads) > 0
        assert any("{{" in p.payload for p in html_payloads)
        
        # Test URL context
        url_payloads = engine.get_payloads_for_context("url")
        assert len(url_payloads) > 0
        
        # Test attribute context
        attr_payloads = engine.get_payloads_for_context("attribute")
        assert len(attr_payloads) > 0
    
    def test_response_analysis(self, engine):
        """Test response analysis methods."""
        original_response = "Search results for: test"
        payload = "{{7*7}}"
        
        # Test math detection
        math_response = "Search results for: 49"
        result = engine.analyze_response(original_response, payload, math_response)
        assert result.is_vulnerable is True
        assert result.confidence == ConfidenceLevel.HIGH
        
        # Test non-vulnerable response
        safe_response = "Search results for: {{7*7}}"
        result = engine.analyze_response(original_response, payload, safe_response)
        assert result.is_vulnerable is False
    
    def test_payload_encoding(self, engine):
        """Test payload encoding for different contexts."""
        base_payload = "{{7*7}}"
        
        # Test URL encoding
        url_payload = engine.encode_payload(base_payload, "url")
        assert "%7B" in url_payload or "{{" in url_payload
        
        # Test HTML encoding
        html_payload = engine.encode_payload(base_payload, "html")
        assert html_payload is not None
        
        # Test attribute encoding
        attr_payload = engine.encode_payload(base_payload, "attribute")
        assert attr_payload is not None
    
    def test_error_handling(self, engine):
        """Test error handling in response analysis."""
        # Test with empty response
        result = engine.analyze_response("original", "{{test}}", "")
        assert result.is_vulnerable is False
        
        # Test with None response
        result = engine.analyze_response("original", "{{test}}", None)
        assert result.is_vulnerable is False
        
        # Test with very long response
        long_response = "x" * 10000
        result = engine.analyze_response("original", "{{test}}", long_response)
        assert result is not None
    
    def test_confidence_calculation(self, engine):
        """Test confidence level calculation."""
        payload = "{{7*7}}"
        
        # High confidence: exact match
        response = "Result: 49"
        result = engine.analyze_response("Result: test", payload, response)
        assert result.confidence == ConfidenceLevel.HIGH
        
        # Medium confidence: partial indicators
        response = "Result: &lt;Config"
        result = engine.analyze_response("Result: test", "{{config}}", response)
        assert result.confidence in [ConfidenceLevel.MEDIUM, ConfidenceLevel.HIGH]
        
        # Low confidence: weak indicators
        response = "Result: template"
        result = engine.analyze_response("Result: test", "{{_self}}", response)
        assert result.confidence == ConfidenceLevel.LOW
    
    def test_payload_filtering(self, engine):
        """Test payload filtering by type and context."""
        # Filter by type
        math_payloads = engine.get_payloads_by_type("math")
        assert len(math_payloads) > 0
        assert all(p.type == "math" for p in math_payloads)
        
        config_payloads = engine.get_payloads_by_type("config_access")
        assert len(config_payloads) > 0
        assert all(p.type == "config_access" for p in config_payloads)
        
        # Filter by context
        html_payloads = engine.get_payloads_for_context("html")
        assert len(html_payloads) > 0
        assert all(p.context == "html" for p in html_payloads)


class TestEngineIntegration:
    """Integration tests for template engines."""
    
    @pytest.mark.asyncio
    async def test_multiple_payload_testing(self):
        """Test running multiple payloads against an endpoint."""
        config = ScanConfig()
        engine = Jinja2Engine(config)
        
        url = "http://example.com/search"
        
        # Mock HTTP client with vulnerable responses
        mock_client = AsyncMock()
        mock_client.get.side_effect = [
            {'status': 200, 'text': "Result: 49", 'headers': {}},  # Math
            {'status': 200, 'text': "Result: <Config", 'headers': {}},  # Config
            {'status': 200, 'text': "Result: test", 'headers': {}},  # Safe
        ]
        
        # Test multiple payloads
        payloads = ["{{7*7}}", "{{config}}", "{{safe_test}}"]
        results = []
        
        for payload in payloads:
            result = await engine.test_payload(url, payload, http_client=mock_client)
            results.append(result)
        
        # Should detect 2 vulnerabilities
        vulnerable_results = [r for r in results if r.is_vulnerable]
        assert len(vulnerable_results) == 2
    
    @pytest.mark.asyncio
    async def test_engine_factory_pattern(self):
        """Test engine factory pattern for creating engines."""
        from src.engines.factory import EngineFactory
        
        config = ScanConfig()
        factory = EngineFactory(config)
        
        # Test creating Jinja2 engine
        jinja2_engine = factory.create_engine("jinja2")
        assert isinstance(jinja2_engine, Jinja2Engine)
        assert jinja2_engine.name == "jinja2"
        
        # Test creating unknown engine
        with pytest.raises(ValueError):
            factory.create_engine("unknown_engine")
    
    def test_engine_comparison(self):
        """Test comparing different engines."""
        config = ScanConfig()
        
        engine1 = Jinja2Engine(config)
        engine2 = Jinja2Engine(config)
        
        # Same engine type should be equal
        assert engine1.name == engine2.name
        assert len(engine1.payloads) == len(engine2.payloads)
    
    def test_engine_serialization(self):
        """Test engine configuration serialization."""
        config = ScanConfig()
        engine = Jinja2Engine(config)
        
        # Test getting engine info
        info = engine.get_info()
        assert info['name'] == 'jinja2'
        assert 'payloads' in info
        assert 'description' in info
        assert isinstance(info['payloads'], int)


class TestEnginePerformance:
    """Performance tests for template engines."""
    
    def test_payload_loading_performance(self):
        """Test payload loading performance."""
        import time
        
        config = ScanConfig()
        
        start_time = time.time()
        engine = Jinja2Engine(config)
        load_time = time.time() - start_time
        
        # Should load quickly
        assert load_time < 1.0  # Less than 1 second
        assert len(engine.payloads) > 10  # Should have reasonable number of payloads
    
    @pytest.mark.asyncio
    async def test_concurrent_payload_testing(self):
        """Test concurrent payload testing performance."""
        import asyncio
        import time
        
        config = ScanConfig()
        engine = Jinja2Engine(config)
        
        # Mock HTTP client
        mock_client = AsyncMock()
        mock_client.get.return_value = {
            'status': 200,
            'text': "Result: test",
            'headers': {}
        }
        
        # Test multiple payloads concurrently
        url = "http://example.com/test"
        payloads = ["{{7*7}}", "{{config}}", "{{request}}", "{{_self}}"]
        
        start_time = time.time()
        tasks = [engine.test_payload(url, payload, http_client=mock_client) 
                for payload in payloads]
        results = await asyncio.gather(*tasks)
        test_time = time.time() - start_time
        
        # Should complete quickly
        assert test_time < 5.0  # Less than 5 seconds
        assert len(results) == len(payloads)
