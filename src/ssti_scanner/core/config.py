"""
Configuration management for SSTI Scanner.

This module handles all configuration aspects including:
- CLI arguments parsing
- Configuration file loading
- Environment variable handling
- Validation and defaults
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import yaml
from pydantic import BaseModel, Field, validator


class CrawlingConfig(BaseModel):
    """Configuration for web crawling behavior."""
    
    depth_limit: int = Field(default=5, ge=1, le=20, description="Maximum crawling depth")
    max_pages: int = Field(default=1000, ge=1, description="Maximum pages to crawl")
    request_delay: float = Field(default=0.5, ge=0.0, description="Delay between requests")
    concurrent_requests: int = Field(default=10, ge=1, le=100, description="Concurrent requests")
    timeout: int = Field(default=30, ge=5, le=300, description="Request timeout in seconds")
    respect_robots_txt: bool = Field(default=True, description="Respect robots.txt")
    follow_redirects: bool = Field(default=True, description="Follow HTTP redirects")
    handle_javascript: bool = Field(default=False, description="Handle JavaScript rendering")
    user_agents: List[str] = Field(
        default_factory=lambda: [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        ]
    )


class ScanningConfig(BaseModel):
    """Configuration for scanning behavior."""
    
    intensity: str = Field(default="normal", regex="^(quick|normal|aggressive)$")
    engines: List[str] = Field(
        default_factory=lambda: [
            "jinja2", "twig", "freemarker", "velocity", 
            "smarty", "thymeleaf", "handlebars", "django"
        ]
    )
    max_payload_length: int = Field(default=1000, ge=10, le=10000)
    blind_detection: bool = Field(default=True, description="Enable blind SSTI detection")
    time_based_detection: bool = Field(default=True, description="Enable time-based detection")
    out_of_band_detection: bool = Field(default=False, description="Enable OOB detection")
    error_based_detection: bool = Field(default=True, description="Enable error-based detection")
    
    @validator('engines')
    def validate_engines(cls, v):
        """Validate template engine names."""
        valid_engines = {
            "jinja2", "twig", "freemarker", "velocity", "smarty", 
            "thymeleaf", "handlebars", "mustache", "erb", "django"
        }
        invalid = set(v) - valid_engines
        if invalid:
            raise ValueError(f"Invalid template engines: {invalid}")
        return v


class AuthConfig(BaseModel):
    """Configuration for authentication."""
    
    auth_type: Optional[str] = Field(default=None, regex="^(basic|bearer|session|custom)$")
    username: Optional[str] = None
    password: Optional[str] = None
    token: Optional[str] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    cookies: Dict[str, str] = Field(default_factory=dict)
    session_file: Optional[Path] = None


class ProxyConfig(BaseModel):
    """Configuration for proxy settings."""
    
    http_proxy: Optional[str] = None
    https_proxy: Optional[str] = None
    proxy_auth: Optional[str] = None
    proxy_rotation: bool = Field(default=False)
    proxy_list: List[str] = Field(default_factory=list)


class OutputConfig(BaseModel):
    """Configuration for output and reporting."""
    
    format: str = Field(default="console", regex="^(console|json|html|csv|xml)$")
    output_file: Optional[Path] = None
    verbose: bool = Field(default=False)
    debug: bool = Field(default=False)
    colored_output: bool = Field(default=True)
    include_payloads: bool = Field(default=True)
    include_requests: bool = Field(default=False)


class Config(BaseModel):
    """Main configuration class for SSTI Scanner."""
    
    # Target configuration
    target_url: Optional[str] = None
    target_file: Optional[Path] = None
    target_scope: List[str] = Field(default_factory=list)
    exclude_patterns: List[str] = Field(default_factory=list)
    
    # Sub-configurations
    crawling: CrawlingConfig = Field(default_factory=CrawlingConfig)
    scanning: ScanningConfig = Field(default_factory=ScanningConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    proxy: ProxyConfig = Field(default_factory=ProxyConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    
    # Advanced options
    safe_mode: bool = Field(default=True, description="Prevent destructive payloads")
    resume_scan: bool = Field(default=False, description="Resume interrupted scan")
    save_state: bool = Field(default=True, description="Save scan state for resume")
    state_file: Optional[Path] = None
    
    class Config:
        """Pydantic configuration."""
        validate_assignment = True
        extra = "forbid"
        
    @classmethod
    def from_file(cls, config_path: Union[str, Path]) -> Config:
        """Load configuration from YAML file."""
        config_path = Path(config_path)
        if not config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
            
        with open(config_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
            
        return cls(**data)
    
    @classmethod
    def from_env(cls) -> Config:
        """Load configuration from environment variables."""
        env_config = {}
        
        # Map environment variables to config structure
        env_mappings = {
            'SSTI_TARGET_URL': 'target_url',
            'SSTI_TARGET_FILE': 'target_file',
            'SSTI_CRAWL_DEPTH': 'crawling.depth_limit',
            'SSTI_SCAN_INTENSITY': 'scanning.intensity',
            'SSTI_OUTPUT_FORMAT': 'output.format',
            'SSTI_OUTPUT_FILE': 'output.output_file',
            'SSTI_VERBOSE': 'output.verbose',
            'SSTI_DEBUG': 'output.debug',
            'SSTI_SAFE_MODE': 'safe_mode',
            'SSTI_PROXY_HTTP': 'proxy.http_proxy',
            'SSTI_PROXY_HTTPS': 'proxy.https_proxy',
            'SSTI_AUTH_TYPE': 'auth.auth_type',
            'SSTI_AUTH_TOKEN': 'auth.token',
        }
        
        for env_var, config_path in env_mappings.items():
            value = os.getenv(env_var)
            if value is not None:
                cls._set_nested_value(env_config, config_path, value)
                
        return cls(**env_config)
    
    @staticmethod
    def _set_nested_value(data: Dict[str, Any], path: str, value: str) -> None:
        """Set nested dictionary value from dot-separated path."""
        keys = path.split('.')
        current = data
        
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
            
        # Type conversion for common types
        final_key = keys[-1]
        if value.lower() in ('true', 'false'):
            current[final_key] = value.lower() == 'true'
        elif value.isdigit():
            current[final_key] = int(value)
        elif value.replace('.', '', 1).isdigit():
            current[final_key] = float(value)
        else:
            current[final_key] = value
    
    def save_to_file(self, config_path: Union[str, Path]) -> None:
        """Save configuration to YAML file."""
        config_path = Path(config_path)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(config_path, 'w', encoding='utf-8') as f:
            yaml.dump(self.dict(), f, default_flow_style=False, indent=2)
    
    def update_from_args(self, **kwargs) -> None:
        """Update configuration from command line arguments."""
        for key, value in kwargs.items():
            if value is not None and hasattr(self, key):
                setattr(self, key, value)
    
    def get_user_agents(self) -> List[str]:
        """Get list of user agents for rotation."""
        return self.crawling.user_agents
    
    def get_request_delay(self) -> float:
        """Get request delay based on intensity level."""
        delay_map = {
            'quick': self.crawling.request_delay * 0.5,
            'normal': self.crawling.request_delay,
            'aggressive': self.crawling.request_delay * 2.0
        }
        return delay_map.get(self.scanning.intensity, self.crawling.request_delay)
    
    def get_concurrent_requests(self) -> int:
        """Get concurrent requests based on intensity level."""
        concurrent_map = {
            'quick': max(1, self.crawling.concurrent_requests // 2),
            'normal': self.crawling.concurrent_requests,
            'aggressive': min(50, self.crawling.concurrent_requests * 2)
        }
        return concurrent_map.get(self.scanning.intensity, self.crawling.concurrent_requests)
    
    def is_engine_enabled(self, engine: str) -> bool:
        """Check if a template engine is enabled."""
        return engine.lower() in [e.lower() for e in self.scanning.engines]
    
    def validate_target(self) -> bool:
        """Validate that at least one target is specified."""
        return bool(self.target_url or self.target_file or self.target_scope)
