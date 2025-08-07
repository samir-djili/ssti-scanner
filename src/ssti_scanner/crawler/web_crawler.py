"""
Web Crawler for SSTI Scanner.

This module provides intelligent web crawling capabilities including:
- Systematic URL discovery
- Form and endpoint enumeration
- JavaScript-rendered content handling
- Respect for robots.txt and rate limiting
"""

from __future__ import annotations

import asyncio
import re
from typing import List, Set, Optional, Dict, Any
from urllib.parse import urljoin, urlparse, parse_qs
from urllib.robotparser import RobotFileParser

import aiohttp
from bs4 import BeautifulSoup

from ssti_scanner.core.config import Config
from ssti_scanner.utils.http_client import AsyncHTTPClient
from ssti_scanner.utils.logger import get_logger
from ssti_scanner.utils.url_utils import is_valid_url, normalize_url, get_domain


class CrawlResult:
    """Results from crawling a single page."""
    
    def __init__(self, url: str, status_code: int, content_type: str = ""):
        self.url = url
        self.status_code = status_code
        self.content_type = content_type
        self.links: Set[str] = set()
        self.forms: List[Dict[str, Any]] = []
        self.javascript_urls: Set[str] = set()
        self.api_endpoints: Set[str] = set()
        self.error_pages: Set[str] = set()


class WebCrawler:
    """
    Intelligent web crawler for SSTI scanning.
    
    Features:
    - Breadth-first and depth-first crawling strategies
    - JavaScript endpoint extraction
    - Form discovery and analysis
    - Robots.txt compliance
    - Rate limiting and politeness
    - Resume capability
    """
    
    def __init__(self, config: Config, http_client: AsyncHTTPClient):
        """Initialize the web crawler."""
        self.config = config
        self.http_client = http_client
        self.logger = get_logger(__name__, config.output.debug)
        
        # Crawling state
        self.visited_urls: Set[str] = set()
        self.discovered_urls: Set[str] = set()
        self.crawl_queue: List[str] = []
        self.robots_cache: Dict[str, RobotFileParser] = {}
        
        # Statistics
        self.pages_crawled = 0
        self.forms_discovered = 0
        self.api_endpoints_discovered = 0
        
        # URL patterns to exclude
        self.exclude_patterns = [
            r'\.(?:css|js|png|jpg|jpeg|gif|svg|ico|pdf|zip|tar|gz)$',
            r'\/logout$',
            r'\/signout$',
            r'\/download\/',
            r'mailto:',
            r'tel:',
        ]
        self.exclude_regex = re.compile('|'.join(self.exclude_patterns), re.IGNORECASE)
    
    async def crawl(self, start_url: str) -> List[str]:
        """
        Crawl website starting from the given URL.
        
        Args:
            start_url: Starting URL for crawling
            
        Returns:
            List of discovered URLs
        """
        self.logger.info(f"Starting crawl from: {start_url}")
        
        # Initialize crawling
        self.crawl_queue = [normalize_url(start_url)]
        self.discovered_urls.add(normalize_url(start_url))
        
        # Load robots.txt
        await self._load_robots_txt(start_url)
        
        # Crawl with depth limit
        current_depth = 0
        
        while self.crawl_queue and current_depth < self.config.crawling.depth_limit:
            if self.pages_crawled >= self.config.crawling.max_pages:
                self.logger.info(f"Reached maximum page limit: {self.config.crawling.max_pages}")
                break
                
            # Get URLs for current depth level
            current_level_urls = self.crawl_queue.copy()
            self.crawl_queue.clear()
            
            # Process URLs concurrently
            await self._process_urls_concurrent(current_level_urls)
            
            current_depth += 1
            
        self.logger.info(f"Crawling completed. Discovered {len(self.discovered_urls)} URLs")
        return list(self.discovered_urls)
    
    async def _process_urls_concurrent(self, urls: List[str]) -> None:
        """Process multiple URLs concurrently."""
        semaphore = asyncio.Semaphore(self.config.get_concurrent_requests())
        
        async def process_with_semaphore(url: str) -> None:
            async with semaphore:
                await self._crawl_single_page(url)
                
        # Process URLs with rate limiting
        tasks = [process_with_semaphore(url) for url in urls]
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _crawl_single_page(self, url: str) -> Optional[CrawlResult]:
        """Crawl a single page and extract information."""
        if url in self.visited_urls:
            return None
            
        if not self._should_crawl_url(url):
            return None
            
        self.visited_urls.add(url)
        
        try:
            # Make request with rate limiting
            await asyncio.sleep(self.config.get_request_delay())
            
            response = await self.http_client.get(url)
            self.pages_crawled += 1
            
            # Create crawl result
            result = CrawlResult(url, response.status_code, response.content_type)
            
            # Parse content if HTML
            if 'text/html' in response.content_type:
                await self._parse_html_content(url, response.text, result)
            
            self.logger.debug(f"Crawled: {url} (status: {response.status_code})")
            return result
            
        except Exception as e:
            self.logger.warning(f"Failed to crawl {url}: {e}")
            return None
    
    async def _parse_html_content(self, base_url: str, content: str, result: CrawlResult) -> None:
        """Parse HTML content and extract links, forms, and other information."""
        try:
            soup = BeautifulSoup(content, 'html.parser')
            
            # Extract links
            await self._extract_links(base_url, soup, result)
            
            # Extract forms
            await self._extract_forms(base_url, soup, result)
            
            # Extract JavaScript information
            await self._extract_javascript_info(base_url, soup, result)
            
            # Look for API endpoints in script tags
            await self._extract_api_endpoints(soup, result)
            
        except Exception as e:
            self.logger.warning(f"Failed to parse HTML content from {base_url}: {e}")
    
    async def _extract_links(self, base_url: str, soup: BeautifulSoup, result: CrawlResult) -> None:
        """Extract all links from the page."""
        # Standard anchor tags
        for link in soup.find_all('a', href=True):
            href = link['href']
            full_url = urljoin(base_url, href)
            normalized_url = normalize_url(full_url)
            
            if self._is_valid_crawl_target(normalized_url):
                result.links.add(normalized_url)
                
                if normalized_url not in self.discovered_urls:
                    self.discovered_urls.add(normalized_url)
                    self.crawl_queue.append(normalized_url)
        
        # Links in other elements
        for element in soup.find_all(['link', 'area', 'base'], href=True):
            href = element['href']
            full_url = urljoin(base_url, href)
            normalized_url = normalize_url(full_url)
            
            if self._is_valid_crawl_target(normalized_url):
                result.links.add(normalized_url)
    
    async def _extract_forms(self, base_url: str, soup: BeautifulSoup, result: CrawlResult) -> None:
        """Extract form information from the page."""
        for form in soup.find_all('form'):
            form_info = {
                'action': urljoin(base_url, form.get('action', '')),
                'method': form.get('method', 'GET').upper(),
                'inputs': [],
                'has_file_upload': False,
            }
            
            # Extract input fields
            for input_elem in form.find_all(['input', 'textarea', 'select']):
                input_info = {
                    'name': input_elem.get('name', ''),
                    'type': input_elem.get('type', 'text'),
                    'value': input_elem.get('value', ''),
                    'placeholder': input_elem.get('placeholder', ''),
                    'required': input_elem.has_attr('required'),
                }
                
                if input_info['type'] == 'file':
                    form_info['has_file_upload'] = True
                    
                if input_info['name']:  # Only include named inputs
                    form_info['inputs'].append(input_info)
            
            if form_info['inputs']:  # Only include forms with inputs
                result.forms.append(form_info)
                self.forms_discovered += 1
    
    async def _extract_javascript_info(self, base_url: str, soup: BeautifulSoup, result: CrawlResult) -> None:
        """Extract JavaScript file URLs and inline script information."""
        # External JavaScript files
        for script in soup.find_all('script', src=True):
            js_url = urljoin(base_url, script['src'])
            result.javascript_urls.add(js_url)
        
        # Inline JavaScript analysis (basic endpoint extraction)
        for script in soup.find_all('script', src=False):
            if script.string:
                await self._analyze_inline_javascript(script.string, result)
    
    async def _analyze_inline_javascript(self, script_content: str, result: CrawlResult) -> None:
        """Analyze inline JavaScript for API endpoints and forms."""
        try:
            # Look for URL patterns in JavaScript
            url_patterns = [
                r'["\']([/][^"\']*)["\']',  # Relative URLs
                r'["\']([a-zA-Z]+://[^"\']*)["\']',  # Absolute URLs
                r'url\s*:\s*["\']([^"\']*)["\']',  # AJAX URL patterns
                r'fetch\s*\(\s*["\']([^"\']*)["\']',  # Fetch API calls
            ]
            
            for pattern in url_patterns:
                matches = re.findall(pattern, script_content, re.IGNORECASE)
                for match in matches:
                    if self._looks_like_api_endpoint(match):
                        result.api_endpoints.add(match)
                        self.api_endpoints_discovered += 1
                        
        except Exception as e:
            self.logger.debug(f"Error analyzing JavaScript: {e}")
    
    async def _extract_api_endpoints(self, soup: BeautifulSoup, result: CrawlResult) -> None:
        """Extract potential API endpoints from various sources."""
        # Look in data attributes
        for element in soup.find_all(attrs={'data-url': True}):
            url = element['data-url']
            if self._looks_like_api_endpoint(url):
                result.api_endpoints.add(url)
        
        # Look in form actions that might be API endpoints
        for form in soup.find_all('form', action=True):
            action = form['action']
            if self._looks_like_api_endpoint(action):
                result.api_endpoints.add(action)
    
    def _looks_like_api_endpoint(self, url: str) -> bool:
        """Determine if a URL looks like an API endpoint."""
        api_indicators = [
            '/api/', '/v1/', '/v2/', '/v3/', '/rest/', '/graphql',
            '.json', '.xml', '/ajax/', '/rpc/'
        ]
        return any(indicator in url.lower() for indicator in api_indicators)
    
    async def _load_robots_txt(self, start_url: str) -> None:
        """Load and parse robots.txt for the domain."""
        if not self.config.crawling.respect_robots_txt:
            return
            
        domain = get_domain(start_url)
        if domain in self.robots_cache:
            return
            
        try:
            robots_url = f"{urlparse(start_url).scheme}://{domain}/robots.txt"
            response = await self.http_client.get(robots_url)
            
            if response.status_code == 200:
                rp = RobotFileParser()
                rp.set_url(robots_url)
                rp.feed(response.text.splitlines())
                self.robots_cache[domain] = rp
                self.logger.debug(f"Loaded robots.txt for {domain}")
            else:
                # No robots.txt found, allow all
                self.robots_cache[domain] = None
                
        except Exception as e:
            self.logger.debug(f"Failed to load robots.txt for {domain}: {e}")
            self.robots_cache[domain] = None
    
    def _should_crawl_url(self, url: str) -> bool:
        """Determine if a URL should be crawled."""
        # Check robots.txt
        if self.config.crawling.respect_robots_txt:
            domain = get_domain(url)
            robots = self.robots_cache.get(domain)
            if robots and not robots.can_fetch('*', url):
                return False
        
        # Check exclude patterns
        if self.exclude_regex.search(url):
            return False
        
        # Check if already visited
        if url in self.visited_urls:
            return False
        
        return True
    
    def _is_valid_crawl_target(self, url: str) -> bool:
        """Check if URL is a valid crawling target."""
        if not is_valid_url(url):
            return False
            
        # Check if in scope (same domain for now)
        start_domain = get_domain(self.config.target_url)
        url_domain = get_domain(url)
        
        if start_domain != url_domain:
            return False
            
        return True
    
    def get_statistics(self) -> Dict[str, int]:
        """Get crawling statistics."""
        return {
            "pages_crawled": self.pages_crawled,
            "urls_discovered": len(self.discovered_urls),
            "forms_discovered": self.forms_discovered,
            "api_endpoints_discovered": self.api_endpoints_discovered,
            "visited_urls": len(self.visited_urls),
        }
