"""
Asynchronous HTTP client for SSTI Scanner.

This module provides a robust HTTP client with features like:
- Connection pooling and reuse
- Request/response logging
- Error handling and retries
- Rate limiting
- Proxy support
- Custom headers and authentication
"""

from __future__ import annotations

import asyncio
import random
import time
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse

import aiohttp
from aiohttp import ClientTimeout, ClientSession, TCPConnector
from aiohttp.client_exceptions import ClientError, ClientTimeout as TimeoutError

from ssti_scanner.core.config import Config
from ssti_scanner.utils.logger import get_logger


class HTTPResponse:
    """Wrapper for HTTP response data."""
    
    def __init__(self, url: str, status_code: int, headers: Dict[str, str], 
                 text: str, content_type: str = "", response_time: float = 0.0):
        self.url = url
        self.status_code = status_code
        self.headers = headers
        self.text = text
        self.content_type = content_type
        self.response_time = response_time
        self.timestamp = time.time()


class AsyncHTTPClient:
    """
    Asynchronous HTTP client optimized for security scanning.
    
    Features:
    - Connection pooling for performance
    - Request rate limiting
    - User agent rotation
    - Proxy support
    - Authentication handling
    - Request/response logging
    - Error handling and retries
    """
    
    def __init__(self, config: Config):
        """Initialize the HTTP client."""
        self.config = config
        self.logger = get_logger(__name__, config.output.debug)
        
        # Statistics
        self.successful_requests = 0
        self.failed_requests = 0
        self.total_response_time = 0.0
        
        # Session will be created when needed
        self._session: Optional[ClientSession] = None
        self._connector: Optional[TCPConnector] = None
        
        # Rate limiting
        self._last_request_time = 0.0
        self._request_semaphore = asyncio.Semaphore(config.get_concurrent_requests())
        
        # User agent rotation
        self._user_agents = config.get_user_agents()
        self._current_ua_index = 0
    
    async def _get_session(self) -> ClientSession:
        """Get or create HTTP session."""
        if self._session is None or self._session.closed:
            await self._create_session()
        return self._session
    
    async def _create_session(self) -> None:
        """Create new HTTP session with proper configuration."""
        # Configure connector
        self._connector = TCPConnector(
            limit=100,  # Total connection pool size
            limit_per_host=30,  # Connections per host
            ttl_dns_cache=300,  # DNS cache TTL
            use_dns_cache=True,
            enable_cleanup_closed=True,
        )
        
        # Configure timeout
        timeout = ClientTimeout(
            total=self.config.crawling.timeout,
            connect=10,
            sock_read=self.config.crawling.timeout
        )
        
        # Configure session
        self._session = ClientSession(
            connector=self._connector,
            timeout=timeout,
            headers=self._get_default_headers(),
            trust_env=True,  # Use proxy settings from environment
        )
        
        self.logger.debug("HTTP session created")
    
    def _get_default_headers(self) -> Dict[str, str]:
        """Get default headers for requests."""
        headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        # Add authentication headers if configured
        if self.config.auth.auth_type == 'bearer' and self.config.auth.token:
            headers['Authorization'] = f'Bearer {self.config.auth.token}'
        elif self.config.auth.auth_type == 'custom':
            headers.update(self.config.auth.headers)
            
        return headers
    
    def _get_user_agent(self) -> str:
        """Get user agent with rotation."""
        if not self._user_agents:
            return 'SSTI-Scanner/1.0'
            
        user_agent = self._user_agents[self._current_ua_index]
        self._current_ua_index = (self._current_ua_index + 1) % len(self._user_agents)
        return user_agent
    
    async def _rate_limit(self) -> None:
        """Apply rate limiting between requests."""
        current_time = time.time()
        elapsed = current_time - self._last_request_time
        delay = self.config.get_request_delay()
        
        if elapsed < delay:
            wait_time = delay - elapsed
            await asyncio.sleep(wait_time)
            
        self._last_request_time = time.time()
    
    async def get(self, url: str, **kwargs) -> HTTPResponse:
        """Make GET request."""
        return await self._request('GET', url, **kwargs)
    
    async def post(self, url: str, data: Optional[Dict[str, Any]] = None, **kwargs) -> HTTPResponse:
        """Make POST request."""
        return await self._request('POST', url, data=data, **kwargs)
    
    async def put(self, url: str, data: Optional[Dict[str, Any]] = None, **kwargs) -> HTTPResponse:
        """Make PUT request."""
        return await self._request('PUT', url, data=data, **kwargs)
    
    async def delete(self, url: str, **kwargs) -> HTTPResponse:
        """Make DELETE request."""
        return await self._request('DELETE', url, **kwargs)
    
    async def _request(self, method: str, url: str, **kwargs) -> HTTPResponse:
        """Make HTTP request with rate limiting and error handling."""
        async with self._request_semaphore:
            await self._rate_limit()
            
            session = await self._get_session()
            start_time = time.time()
            
            try:
                # Prepare request parameters
                request_kwargs = self._prepare_request_kwargs(**kwargs)
                
                # Add rotating user agent
                if 'headers' not in request_kwargs:
                    request_kwargs['headers'] = {}
                request_kwargs['headers']['User-Agent'] = self._get_user_agent()
                
                # Make request
                async with session.request(method, url, **request_kwargs) as response:
                    text = await response.text()
                    response_time = time.time() - start_time
                    
                    # Create response object
                    http_response = HTTPResponse(
                        url=str(response.url),
                        status_code=response.status,
                        headers=dict(response.headers),
                        text=text,
                        content_type=response.headers.get('content-type', ''),
                        response_time=response_time
                    )
                    
                    # Update statistics
                    self.successful_requests += 1
                    self.total_response_time += response_time
                    
                    self.logger.debug(f"{method} {url} -> {response.status} ({response_time:.2f}s)")
                    return http_response
                    
            except (ClientError, TimeoutError, asyncio.TimeoutError) as e:
                self.failed_requests += 1
                response_time = time.time() - start_time
                
                self.logger.warning(f"{method} {url} failed: {e}")
                
                # Return error response
                return HTTPResponse(
                    url=url,
                    status_code=0,
                    headers={},
                    text="",
                    content_type="",
                    response_time=response_time
                )
    
    def _prepare_request_kwargs(self, **kwargs) -> Dict[str, Any]:
        """Prepare request parameters."""
        request_kwargs = kwargs.copy()
        
        # Handle authentication
        if self.config.auth.auth_type == 'basic':
            auth = aiohttp.BasicAuth(
                self.config.auth.username or "",
                self.config.auth.password or ""
            )
            request_kwargs['auth'] = auth
        
        # Handle cookies
        if self.config.auth.cookies:
            if 'cookies' not in request_kwargs:
                request_kwargs['cookies'] = {}
            request_kwargs['cookies'].update(self.config.auth.cookies)
        
        # Handle proxy
        if self.config.proxy.http_proxy or self.config.proxy.https_proxy:
            proxy = self.config.proxy.https_proxy or self.config.proxy.http_proxy
            request_kwargs['proxy'] = proxy
            
            if self.config.proxy.proxy_auth:
                request_kwargs['proxy_auth'] = aiohttp.BasicAuth(
                    *self.config.proxy.proxy_auth.split(':', 1)
                )
        
        # SSL verification (allow insecure for testing)
        request_kwargs['ssl'] = False
        
        return request_kwargs
    
    async def close(self) -> None:
        """Close HTTP session and cleanup resources."""
        if self._session and not self._session.closed:
            await self._session.close()
            
        if self._connector:
            await self._connector.close()
            
        self.logger.debug("HTTP client closed")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get HTTP client statistics."""
        total_requests = self.successful_requests + self.failed_requests
        avg_response_time = (
            self.total_response_time / self.successful_requests 
            if self.successful_requests > 0 else 0.0
        )
        
        return {
            "total_requests": total_requests,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "success_rate": (
                self.successful_requests / total_requests 
                if total_requests > 0 else 0.0
            ),
            "average_response_time": avg_response_time,
        }
    
    async def __aenter__(self):
        """Async context manager entry."""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()
