"""
URL List Processor for SSTI Scanner.

This module handles processing of URL lists from text files,
supporting various formats and validation.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Dict, Optional, Set, Any
from urllib.parse import urlparse, parse_qs
from dataclasses import dataclass

from ssti_scanner.utils.logger import get_logger
from ssti_scanner.utils.validators import is_valid_url


@dataclass
class URLEntry:
    """Represents a URL entry with metadata."""
    url: str
    method: str = "GET"
    headers: Dict[str, str] = None
    data: Dict[str, Any] = None
    params: Dict[str, str] = None
    cookies: Dict[str, str] = None
    source: str = "file"
    line_number: int = 0
    
    def __post_init__(self):
        if self.headers is None:
            self.headers = {}
        if self.data is None:
            self.data = {}
        if self.params is None:
            self.params = {}
        if self.cookies is None:
            self.cookies = {}


class URLListProcessor:
    """
    Processes URL lists from various text file formats.
    
    Supported formats:
    - Simple URL list (one URL per line)
    - Extended format with method and parameters
    - Burp Suite style requests
    - Comments and metadata
    """
    
    def __init__(self, debug: bool = False):
        """Initialize URL list processor."""
        self.logger = get_logger(__name__, debug)
        self.processed_urls: List[URLEntry] = []
        self.stats = {
            'total_lines': 0,
            'valid_urls': 0,
            'invalid_urls': 0,
            'comments': 0,
            'empty_lines': 0
        }
    
    def process_file(self, file_path: str) -> List[URLEntry]:
        """
        Process URL list file and return list of URL entries.
        
        Args:
            file_path: Path to the URL list file
            
        Returns:
            List of URLEntry objects
            
        Raises:
            FileNotFoundError: If file doesn't exist
            ValueError: If file format is invalid
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"URL list file not found: {file_path}")
        
        self.logger.info(f"Processing URL list file: {file_path}")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            return self._process_lines(lines)
            
        except UnicodeDecodeError:
            # Try with different encoding
            self.logger.warning(f"UTF-8 decode failed, trying latin-1 encoding")
            with open(file_path, 'r', encoding='latin-1') as f:
                lines = f.readlines()
            
            return self._process_lines(lines)
    
    def _process_lines(self, lines: List[str]) -> List[URLEntry]:
        """Process individual lines from file."""
        self.processed_urls.clear()
        self.stats = {k: 0 for k in self.stats.keys()}
        
        for line_num, line in enumerate(lines, 1):
            self.stats['total_lines'] += 1
            line = line.strip()
            
            # Skip empty lines
            if not line:
                self.stats['empty_lines'] += 1
                continue
            
            # Skip comments
            if line.startswith('#') or line.startswith('//'):
                self.stats['comments'] += 1
                continue
            
            # Process the line
            url_entry = self._parse_line(line, line_num)
            if url_entry:
                self.processed_urls.append(url_entry)
                self.stats['valid_urls'] += 1
            else:
                self.stats['invalid_urls'] += 1
        
        self.logger.info(f"Processed {self.stats['valid_urls']} valid URLs from {self.stats['total_lines']} lines")
        return self.processed_urls
    
    def _parse_line(self, line: str, line_num: int) -> Optional[URLEntry]:
        """
        Parse a single line and create URLEntry.
        
        Supported formats:
        - https://example.com
        - GET https://example.com
        - POST https://example.com data=value
        - https://example.com?param=value
        - https://example.com [method=POST,data={"key":"value"}]
        """
        try:
            # Check for extended format with brackets
            if '[' in line and ']' in line:
                return self._parse_extended_format(line, line_num)
            
            # Check for method prefix
            if line.upper().startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'PATCH ', 'HEAD ', 'OPTIONS ')):
                return self._parse_method_format(line, line_num)
            
            # Simple URL format
            if is_valid_url(line):
                return URLEntry(
                    url=line,
                    method="GET",
                    source="file",
                    line_number=line_num
                )
            
            self.logger.warning(f"Invalid URL format at line {line_num}: {line}")
            return None
            
        except Exception as e:
            self.logger.error(f"Error parsing line {line_num}: {e}")
            return None
    
    def _parse_extended_format(self, line: str, line_num: int) -> Optional[URLEntry]:
        """
        Parse extended format: URL [method=POST,data={"key":"value"}]
        """
        # Extract URL and metadata
        url_part = line.split('[')[0].strip()
        metadata_part = line.split('[')[1].split(']')[0]
        
        if not is_valid_url(url_part):
            return None
        
        url_entry = URLEntry(
            url=url_part,
            source="file",
            line_number=line_num
        )
        
        # Parse metadata
        for item in metadata_part.split(','):
            if '=' in item:
                key, value = item.strip().split('=', 1)
                key = key.strip().lower()
                value = value.strip()
                
                if key == 'method':
                    url_entry.method = value.upper()
                elif key == 'data':
                    url_entry.data = self._parse_data_value(value)
                elif key == 'headers':
                    url_entry.headers = self._parse_headers_value(value)
                elif key == 'cookies':
                    url_entry.cookies = self._parse_cookies_value(value)
        
        return url_entry
    
    def _parse_method_format(self, line: str, line_num: int) -> Optional[URLEntry]:
        """
        Parse method format: GET https://example.com
        """
        parts = line.split(' ', 1)
        if len(parts) != 2:
            return None
        
        method, url_and_data = parts
        method = method.upper()
        
        # Check if there's data after the URL
        url_parts = url_and_data.split(' ', 1)
        url = url_parts[0]
        
        if not is_valid_url(url):
            return None
        
        url_entry = URLEntry(
            url=url,
            method=method,
            source="file",
            line_number=line_num
        )
        
        # Parse additional data if present
        if len(url_parts) > 1:
            data_part = url_parts[1]
            url_entry.data = self._parse_simple_data(data_part)
        
        return url_entry
    
    def _parse_data_value(self, value: str) -> Dict[str, Any]:
        """Parse data value (JSON or simple key=value format)."""
        import json
        
        # Try JSON first
        if value.startswith('{') and value.endswith('}'):
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                pass
        
        # Parse simple key=value format
        data = {}
        for pair in value.split('&'):
            if '=' in pair:
                key, val = pair.split('=', 1)
                data[key.strip()] = val.strip()
        
        return data
    
    def _parse_headers_value(self, value: str) -> Dict[str, str]:
        """Parse headers value."""
        import json
        
        if value.startswith('{') and value.endswith('}'):
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                pass
        
        # Parse simple format
        headers = {}
        for pair in value.split(','):
            if ':' in pair:
                key, val = pair.split(':', 1)
                headers[key.strip()] = val.strip()
        
        return headers
    
    def _parse_cookies_value(self, value: str) -> Dict[str, str]:
        """Parse cookies value."""
        cookies = {}
        for pair in value.split(';'):
            if '=' in pair:
                key, val = pair.split('=', 1)
                cookies[key.strip()] = val.strip()
        
        return cookies
    
    def _parse_simple_data(self, data_part: str) -> Dict[str, Any]:
        """Parse simple data format: key=value key2=value2"""
        data = {}
        for pair in data_part.split(' '):
            if '=' in pair:
                key, value = pair.split('=', 1)
                data[key.strip()] = value.strip()
        
        return data
    
    def filter_by_domain(self, domains: List[str]) -> List[URLEntry]:
        """Filter URLs by allowed domains."""
        if not domains:
            return self.processed_urls
        
        allowed_domains = set(domain.lower() for domain in domains)
        filtered_urls = []
        
        for url_entry in self.processed_urls:
            parsed = urlparse(url_entry.url)
            if parsed.netloc.lower() in allowed_domains:
                filtered_urls.append(url_entry)
        
        self.logger.info(f"Filtered to {len(filtered_urls)} URLs from allowed domains")
        return filtered_urls
    
    def filter_by_scheme(self, schemes: List[str]) -> List[URLEntry]:
        """Filter URLs by allowed schemes (http, https)."""
        if not schemes:
            return self.processed_urls
        
        allowed_schemes = set(scheme.lower() for scheme in schemes)
        filtered_urls = []
        
        for url_entry in self.processed_urls:
            parsed = urlparse(url_entry.url)
            if parsed.scheme.lower() in allowed_schemes:
                filtered_urls.append(url_entry)
        
        return filtered_urls
    
    def deduplicate_urls(self) -> List[URLEntry]:
        """Remove duplicate URLs while preserving order."""
        seen_urls = set()
        unique_urls = []
        
        for url_entry in self.processed_urls:
            # Create a key based on URL and method
            key = f"{url_entry.method}:{url_entry.url}"
            if key not in seen_urls:
                seen_urls.add(key)
                unique_urls.append(url_entry)
        
        duplicates_removed = len(self.processed_urls) - len(unique_urls)
        if duplicates_removed > 0:
            self.logger.info(f"Removed {duplicates_removed} duplicate URLs")
        
        return unique_urls
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get processing statistics."""
        return {
            **self.stats,
            'unique_domains': len(set(urlparse(url.url).netloc for url in self.processed_urls)),
            'methods_used': list(set(url.method for url in self.processed_urls)),
            'urls_with_parameters': len([url for url in self.processed_urls if url.params or url.data]),
        }
    
    def export_processed_urls(self, output_file: str, format: str = "simple") -> None:
        """
        Export processed URLs to file.
        
        Args:
            output_file: Output file path
            format: Export format (simple, extended, json)
        """
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        if format == "json":
            self._export_json(output_path)
        elif format == "extended":
            self._export_extended(output_path)
        else:
            self._export_simple(output_path)
        
        self.logger.info(f"Exported {len(self.processed_urls)} URLs to {output_path}")
    
    def _export_simple(self, output_path: Path) -> None:
        """Export simple URL list."""
        with open(output_path, 'w', encoding='utf-8') as f:
            for url_entry in self.processed_urls:
                f.write(f"{url_entry.url}\n")
    
    def _export_extended(self, output_path: Path) -> None:
        """Export extended format with metadata."""
        with open(output_path, 'w', encoding='utf-8') as f:
            for url_entry in self.processed_urls:
                line = f"{url_entry.method} {url_entry.url}"
                
                if url_entry.data:
                    data_str = "&".join(f"{k}={v}" for k, v in url_entry.data.items())
                    line += f" {data_str}"
                
                f.write(f"{line}\n")
    
    def _export_json(self, output_path: Path) -> None:
        """Export as JSON."""
        import json
        
        data = []
        for url_entry in self.processed_urls:
            data.append({
                'url': url_entry.url,
                'method': url_entry.method,
                'headers': url_entry.headers,
                'data': url_entry.data,
                'params': url_entry.params,
                'cookies': url_entry.cookies,
                'source': url_entry.source,
                'line_number': url_entry.line_number
            })
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
