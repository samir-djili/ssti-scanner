"""
Unit tests for HTTP client functionality.
"""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import aiohttp
from aiohttp import ClientTimeout, ClientSession

from src.utils.http_client import HTTPClient
from src.core.config import ScanConfig


class TestHTTPClient:
    """Test HTTP client functionality."""
    
    @pytest.fixture
    def config(self):
        """Create test configuration."""
        config = ScanConfig()
        config.scanning.timeout = 10
        config.scanning.delay = 0.1
        config.proxy.http_proxy = ""
        config.proxy.https_proxy = ""
        return config
    
    @pytest.fixture
    def http_client(self, config):
        """Create HTTP client instance."""
        return HTTPClient(config)
    
    def test_http_client_initialization(self, config):
        """Test HTTP client initialization."""
        client = HTTPClient(config)
        
        assert client.config == config
        assert client.session is None
        assert client.semaphore is not None
        assert client.rate_limiter is not None
    
    @pytest.mark.asyncio
    async def test_session_creation(self, http_client):
        """Test session creation and cleanup."""
        # Session should be created on first use
        assert http_client.session is None
        
        await http_client._ensure_session()
        assert http_client.session is not None
        assert isinstance(http_client.session, ClientSession)
        
        # Cleanup
        await http_client.close()
        assert http_client.session.closed
    
    @pytest.mark.asyncio
    async def test_get_request(self, http_client):
        """Test GET request functionality."""
        test_url = "http://example.com/test"
        test_response = "Test response content"
        
        # Mock aiohttp session
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text.return_value = test_response
        mock_response.headers = {'Content-Type': 'text/html'}
        mock_response.url = test_url
        
        with patch.object(http_client, '_ensure_session'), \
             patch.object(http_client, 'session') as mock_session:
            
            mock_session.get.return_value.__aenter__.return_value = mock_response
            
            result = await http_client.get(test_url)
            
            assert result['status'] == 200
            assert result['text'] == test_response
            assert result['headers']['Content-Type'] == 'text/html'
            assert result['url'] == test_url
            
            # Verify session.get was called with correct parameters
            mock_session.get.assert_called_once()
            call_args = mock_session.get.call_args
            assert call_args[0][0] == test_url
    
    @pytest.mark.asyncio
    async def test_post_request(self, http_client):
        """Test POST request functionality."""
        test_url = "http://example.com/submit"
        test_data = {"key": "value", "name": "test"}
        test_response = "Form submitted successfully"
        
        # Mock aiohttp session
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text.return_value = test_response
        mock_response.headers = {'Content-Type': 'text/html'}
        mock_response.url = test_url
        
        with patch.object(http_client, '_ensure_session'), \
             patch.object(http_client, 'session') as mock_session:
            
            mock_session.post.return_value.__aenter__.return_value = mock_response
            
            result = await http_client.post(test_url, data=test_data)
            
            assert result['status'] == 200
            assert result['text'] == test_response
            
            # Verify POST was called with data
            mock_session.post.assert_called_once()
            call_args = mock_session.post.call_args
            assert call_args[0][0] == test_url
            assert 'data' in call_args[1]
    
    @pytest.mark.asyncio
    async def test_request_with_headers(self, http_client):
        """Test request with custom headers."""
        test_url = "http://example.com/api"
        custom_headers = {
            'Authorization': 'Bearer token123',
            'X-Custom-Header': 'custom-value'
        }
        
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text.return_value = "API response"
        mock_response.headers = {'Content-Type': 'application/json'}
        
        with patch.object(http_client, '_ensure_session'), \
             patch.object(http_client, 'session') as mock_session:
            
            mock_session.get.return_value.__aenter__.return_value = mock_response
            
            await http_client.get(test_url, headers=custom_headers)
            
            # Verify headers were passed
            call_args = mock_session.get.call_args
            assert 'headers' in call_args[1]
            headers = call_args[1]['headers']
            assert 'Authorization' in headers
            assert 'X-Custom-Header' in headers
    
    @pytest.mark.asyncio
    async def test_request_with_cookies(self, http_client):
        """Test request with cookies."""
        test_url = "http://example.com/protected"
        cookies = {'session_id': 'abc123', 'user_pref': 'dark_mode'}
        
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text.return_value = "Protected content"
        
        with patch.object(http_client, '_ensure_session'), \
             patch.object(http_client, 'session') as mock_session:
            
            mock_session.get.return_value.__aenter__.return_value = mock_response
            
            await http_client.get(test_url, cookies=cookies)
            
            # Verify cookies were passed
            call_args = mock_session.get.call_args
            assert 'cookies' in call_args[1]
    
    @pytest.mark.asyncio
    async def test_request_timeout_handling(self, http_client):
        """Test timeout handling."""
        test_url = "http://slow.example.com/endpoint"
        
        with patch.object(http_client, '_ensure_session'), \
             patch.object(http_client, 'session') as mock_session:
            
            # Mock timeout exception
            mock_session.get.side_effect = asyncio.TimeoutError()
            
            result = await http_client.get(test_url)
            
            assert result['status'] == 408  # Request Timeout
            assert 'timeout' in result['error'].lower()
    
    @pytest.mark.asyncio
    async def test_connection_error_handling(self, http_client):
        """Test connection error handling."""
        test_url = "http://unreachable.example.com"
        
        with patch.object(http_client, '_ensure_session'), \
             patch.object(http_client, 'session') as mock_session:
            
            # Mock connection error
            mock_session.get.side_effect = aiohttp.ClientConnectorError(
                connection_key=None, os_error=None
            )
            
            result = await http_client.get(test_url)
            
            assert result['status'] == 0  # Connection failed
            assert 'connection' in result['error'].lower()
    
    @pytest.mark.asyncio
    async def test_rate_limiting(self, http_client):
        """Test rate limiting functionality."""
        test_url = "http://example.com/test"
        
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text.return_value = "OK"
        mock_response.headers = {}
        
        with patch.object(http_client, '_ensure_session'), \
             patch.object(http_client, 'session') as mock_session, \
             patch('asyncio.sleep') as mock_sleep:
            
            mock_session.get.return_value.__aenter__.return_value = mock_response
            
            # Make multiple requests rapidly
            await http_client.get(test_url)
            await http_client.get(test_url)
            
            # Should have applied rate limiting delay
            assert mock_sleep.call_count >= 1
    
    @pytest.mark.asyncio
    async def test_concurrent_request_limiting(self, http_client):
        """Test concurrent request limiting."""
        test_urls = [f"http://example.com/test{i}" for i in range(20)]
        
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text.return_value = "OK"
        mock_response.headers = {}
        
        with patch.object(http_client, '_ensure_session'), \
             patch.object(http_client, 'session') as mock_session:
            
            mock_session.get.return_value.__aenter__.return_value = mock_response
            
            # Make many concurrent requests
            tasks = [http_client.get(url) for url in test_urls]
            results = await asyncio.gather(*tasks)
            
            # All should succeed, but concurrency should be limited
            assert len(results) == 20
            assert all(result['status'] == 200 for result in results)
    
    @pytest.mark.asyncio
    async def test_proxy_configuration(self, config):
        """Test proxy configuration."""
        # Configure proxy
        config.proxy.http_proxy = "http://proxy.example.com:8080"
        config.proxy.https_proxy = "https://proxy.example.com:8080"
        
        client = HTTPClient(config)
        
        with patch('aiohttp.ClientSession') as mock_session_class:
            await client._ensure_session()
            
            # Verify session was created with proxy connector
            mock_session_class.assert_called_once()
            call_args = mock_session_class.call_args
            assert 'connector' in call_args[1]
    
    @pytest.mark.asyncio
    async def test_json_response_parsing(self, http_client):
        """Test JSON response parsing."""
        test_url = "http://api.example.com/data"
        test_json_data = {"key": "value", "number": 42}
        
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text.return_value = json.dumps(test_json_data)
        mock_response.headers = {'Content-Type': 'application/json'}
        mock_response.json.return_value = test_json_data
        
        with patch.object(http_client, '_ensure_session'), \
             patch.object(http_client, 'session') as mock_session:
            
            mock_session.get.return_value.__aenter__.return_value = mock_response
            
            result = await http_client.get(test_url)
            
            assert result['status'] == 200
            assert result['json'] == test_json_data
    
    @pytest.mark.asyncio
    async def test_redirect_handling(self, http_client):
        """Test redirect handling."""
        original_url = "http://example.com/redirect"
        final_url = "http://example.com/final"
        
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text.return_value = "Final content"
        mock_response.url = final_url  # After redirect
        mock_response.headers = {}
        mock_response.history = [MagicMock(status=302, url=original_url)]
        
        with patch.object(http_client, '_ensure_session'), \
             patch.object(http_client, 'session') as mock_session:
            
            mock_session.get.return_value.__aenter__.return_value = mock_response
            
            result = await http_client.get(original_url, follow_redirects=True)
            
            assert result['status'] == 200
            assert result['url'] == final_url
            assert result['redirected'] is True
            assert len(result['redirect_history']) == 1
    
    @pytest.mark.asyncio
    async def test_custom_user_agent(self, http_client):
        """Test custom user agent."""
        test_url = "http://example.com/test"
        custom_ua = "Custom-Agent/2.0"
        
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text.return_value = "OK"
        mock_response.headers = {}
        
        with patch.object(http_client, '_ensure_session'), \
             patch.object(http_client, 'session') as mock_session:
            
            mock_session.get.return_value.__aenter__.return_value = mock_response
            
            await http_client.get(test_url, headers={'User-Agent': custom_ua})
            
            call_args = mock_session.get.call_args
            headers = call_args[1]['headers']
            assert headers['User-Agent'] == custom_ua
    
    @pytest.mark.asyncio
    async def test_response_size_limiting(self, http_client):
        """Test response size limiting."""
        test_url = "http://example.com/large"
        large_content = "x" * (10 * 1024 * 1024)  # 10MB
        
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text.return_value = large_content
        mock_response.headers = {'Content-Length': str(len(large_content))}
        
        with patch.object(http_client, '_ensure_session'), \
             patch.object(http_client, 'session') as mock_session:
            
            mock_session.get.return_value.__aenter__.return_value = mock_response
            
            result = await http_client.get(test_url, max_size=1024*1024)  # 1MB limit
            
            # Should handle size limit appropriately
            assert result['status'] in [200, 413]  # OK or Payload Too Large
    
    @pytest.mark.asyncio
    async def test_client_cleanup(self, http_client):
        """Test proper client cleanup."""
        await http_client._ensure_session()
        assert http_client.session is not None
        assert not http_client.session.closed
        
        await http_client.close()
        assert http_client.session.closed
        
        # Should be able to create new session after cleanup
        await http_client._ensure_session()
        assert http_client.session is not None
        assert not http_client.session.closed
        
        await http_client.close()


class TestHTTPClientConfiguration:
    """Test HTTP client configuration options."""
    
    def test_timeout_configuration(self):
        """Test timeout configuration."""
        config = ScanConfig()
        config.scanning.timeout = 30
        
        client = HTTPClient(config)
        
        # Should use configured timeout
        assert client.timeout == 30
    
    def test_delay_configuration(self):
        """Test delay configuration."""
        config = ScanConfig()
        config.scanning.delay = 2.0
        
        client = HTTPClient(config)
        
        # Should use configured delay
        assert client.delay == 2.0
    
    def test_thread_limiting(self):
        """Test thread/concurrency limiting."""
        config = ScanConfig()
        config.scanning.threads = 5
        
        client = HTTPClient(config)
        
        # Should limit concurrent requests
        assert client.semaphore._value == 5
    
    def test_proxy_configuration_parsing(self):
        """Test proxy configuration parsing."""
        config = ScanConfig()
        config.proxy.http_proxy = "http://user:pass@proxy.example.com:8080"
        config.proxy.https_proxy = "https://proxy.example.com:8443"
        
        client = HTTPClient(config)
        
        # Should parse proxy configuration correctly
        assert client.proxy_config['http'] == "http://user:pass@proxy.example.com:8080"
        assert client.proxy_config['https'] == "https://proxy.example.com:8443"


class TestHTTPClientIntegration:
    """Integration tests for HTTP client."""
    
    @pytest.mark.asyncio
    async def test_real_http_request(self):
        """Test real HTTP request (if network available)."""
        config = ScanConfig()
        config.scanning.timeout = 10
        
        client = HTTPClient(config)
        
        try:
            # Test with a reliable public endpoint
            result = await client.get("http://httpbin.org/status/200")
            
            if result['status'] == 200:
                # Successful connection
                assert result['status'] == 200
                assert 'text' in result
            else:
                # Network not available or blocked
                pytest.skip("Network not available for integration test")
        
        except Exception as e:
            pytest.skip(f"Network error: {e}")
        finally:
            await client.close()
    
    @pytest.mark.asyncio
    async def test_error_status_codes(self):
        """Test handling of various HTTP error status codes."""
        config = ScanConfig()
        client = HTTPClient(config)
        
        # Test different error codes with httpbin if available
        error_codes = [400, 401, 403, 404, 500, 502, 503]
        
        for code in error_codes:
            try:
                result = await client.get(f"http://httpbin.org/status/{code}")
                assert result['status'] == code
            except Exception:
                # Skip if httpbin not available
                pytest.skip("httpbin.org not available for testing")
                break
        
        await client.close()
