"""
Main SSTI Scanner class.

This module contains the core scanner logic that orchestrates all scanning operations
including crawling, form analysis, payload injection, and result correlation.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from typing import Dict, List, Optional, Set

from .config import Config
from .result import ScanResult, ScanStatistics
from ..crawler.web_crawler import WebCrawler
from .form_analyzer import FormAnalyzer
from .engine_manager import EngineManager
from ..payloads.payload_manager import PayloadManager
from ..detectors.detection_engine import DetectionEngine
from .result_correlator import ResultCorrelator
from ..utils.logger import get_logger
from ..utils.http_client import AsyncHTTPClient


class SSTIScanner:
    """
    Main SSTI Scanner class that orchestrates the complete scanning process.
    
    This class coordinates all scanning components:
    - Web crawling and discovery
    - Form analysis and injection point identification  
    - Payload generation and injection
    - Result detection and correlation
    - Vulnerability validation and reporting
    """
    
    def __init__(self, config: Config):
        """Initialize the SSTI Scanner with configuration."""
        self.config = config
        self.scan_id = str(uuid.uuid4())
        self.logger = get_logger(__name__, self.config.output.debug)
        
        # Initialize components
        self.http_client = AsyncHTTPClient(config)
        self.crawler = WebCrawler(config, self.http_client)
        self.form_analyzer = FormAnalyzer(config)
        self.engine_manager = EngineManager(config)
        self.payload_manager = PayloadManager(config)
        self.detection_engine = DetectionEngine(config, self.http_client)
        self.result_correlator = ResultCorrelator(config)
        
        # Scan state
        self.scan_result = ScanResult(
            scan_id=self.scan_id,
            config_summary=self._get_config_summary()
        )
        self.is_running = False
        self.should_stop = False
        
        # Tracking sets
        self.discovered_urls: Set[str] = set()
        self.analyzed_forms: Set[str] = set()
        self.tested_injection_points: Set[str] = set()
        
        self.logger.info(f"SSTI Scanner initialized with scan ID: {self.scan_id}")
    
    async def scan(self, target: Optional[str] = None) -> ScanResult:
        """
        Execute complete SSTI scan.
        
        Args:
            target: Optional target URL to override config
            
        Returns:
            ScanResult: Complete scan results
        """
        if self.is_running:
            raise RuntimeError("Scanner is already running")
            
        self.is_running = True
        self.should_stop = False
        
        try:
            # Update target if provided
            if target:
                self.config.target_url = target
                
            # Validate configuration
            if not self.config.validate_target():
                raise ValueError("No valid target specified")
                
            self.logger.info(f"Starting SSTI scan for target: {self.config.target_url}")
            
            # Phase 1: Discovery and Crawling
            await self._discovery_phase()
            
            # Phase 2: Form Analysis and Injection Point Identification
            await self._analysis_phase()
            
            # Phase 3: Payload Injection and Detection
            await self._injection_phase()
            
            # Phase 4: Result Correlation and Validation
            await self._correlation_phase()
            
            # Phase 5: Final Report Generation
            await self._finalization_phase()
            
            self.logger.info("SSTI scan completed successfully")
            
        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            self.scan_result.error_messages.append(str(e))
            raise
        finally:
            self.is_running = False
            self.scan_result.finalize_scan()
            
        return self.scan_result
    
    async def _discovery_phase(self) -> None:
        """Phase 1: Web application discovery and crawling."""
        self.logger.info("Starting discovery phase...")
        
        # Crawl target application
        discovered_urls = await self.crawler.crawl(self.config.target_url)
        self.discovered_urls.update(discovered_urls)
        
        # Update statistics
        self.scan_result.statistics.urls_discovered = len(self.discovered_urls)
        
        self.logger.info(f"Discovery phase completed. Found {len(self.discovered_urls)} URLs")
    
    async def _analysis_phase(self) -> None:
        """Phase 2: Form analysis and injection point identification."""
        self.logger.info("Starting analysis phase...")
        
        injection_points = []
        
        # Analyze each discovered URL
        for url in self.discovered_urls:
            if self.should_stop:
                break
                
            try:
                # Get page content
                response = await self.http_client.get(url)
                
                # Analyze forms and inputs
                forms = await self.form_analyzer.analyze_page(url, response.text)
                
                # Extract injection points from forms
                for form in forms:
                    form_key = f"{url}#{form.action}"
                    if form_key not in self.analyzed_forms:
                        self.analyzed_forms.add(form_key)
                        
                        # Get injection points from form
                        points = self.form_analyzer.get_injection_points(form)
                        injection_points.extend(points)
                        
            except Exception as e:
                self.logger.warning(f"Failed to analyze {url}: {e}")
                
        # Store injection points for testing
        self.injection_points = injection_points
        
        # Update statistics
        self.scan_result.statistics.forms_analyzed = len(self.analyzed_forms)
        self.scan_result.statistics.injection_points_tested = len(injection_points)
        
        self.logger.info(f"Analysis phase completed. Found {len(injection_points)} injection points")
    
    async def _injection_phase(self) -> None:
        """Phase 3: Payload injection and initial detection."""
        self.logger.info("Starting injection phase...")
        
        # Process injection points in batches for performance
        batch_size = self.config.get_concurrent_requests()
        injection_batches = [
            self.injection_points[i:i + batch_size] 
            for i in range(0, len(self.injection_points), batch_size)
        ]
        
        for batch in injection_batches:
            if self.should_stop:
                break
                
            # Process batch concurrently
            tasks = [self._test_injection_point(point) for point in batch]
            await asyncio.gather(*tasks, return_exceptions=True)
            
            # Add delay between batches
            await asyncio.sleep(self.config.get_request_delay())
        
        self.logger.info("Injection phase completed")
    
    async def _test_injection_point(self, injection_point) -> None:
        """Test a single injection point with various payloads."""
        try:
            # Generate appropriate payloads for this injection point
            payloads = await self.payload_manager.generate_payloads(
                injection_point, 
                self.config.scanning.engines
            )
            
            # Test each payload
            for payload_info in payloads:
                if self.should_stop:
                    break
                    
                # Inject payload and detect results
                vulnerability = await self.detection_engine.test_payload(
                    injection_point, 
                    payload_info
                )
                
                if vulnerability:
                    # Add to results for further correlation
                    self.result_correlator.add_potential_vulnerability(vulnerability)
                    
                # Update statistics
                self.scan_result.statistics.payloads_tested += 1
                
                # Rate limiting
                await asyncio.sleep(self.config.get_request_delay())
                
        except Exception as e:
            self.logger.warning(f"Failed to test injection point {injection_point}: {e}")
    
    async def _correlation_phase(self) -> None:
        """Phase 4: Result correlation and validation."""
        self.logger.info("Starting correlation phase...")
        
        # Correlate and validate potential vulnerabilities
        validated_vulnerabilities = await self.result_correlator.correlate_and_validate()
        
        # Add validated vulnerabilities to results
        for vulnerability in validated_vulnerabilities:
            self.scan_result.add_vulnerability(vulnerability)
            
        self.logger.info(f"Correlation phase completed. Validated {len(validated_vulnerabilities)} vulnerabilities")
    
    async def _finalization_phase(self) -> None:
        """Phase 5: Final report generation and cleanup."""
        self.logger.info("Starting finalization phase...")
        
        # Generate final statistics
        self.scan_result.statistics.successful_requests = self.http_client.successful_requests
        self.scan_result.statistics.failed_requests = self.http_client.failed_requests
        self.scan_result.statistics.total_requests = (
            self.http_client.successful_requests + self.http_client.failed_requests
        )
        
        # Cleanup resources
        await self.http_client.close()
        
        self.logger.info("Finalization phase completed")
    
    def stop_scan(self) -> None:
        """Stop the running scan gracefully."""
        self.logger.info("Stopping scan...")
        self.should_stop = True
    
    def get_scan_progress(self) -> Dict[str, any]:
        """Get current scan progress information."""
        return {
            "scan_id": self.scan_id,
            "is_running": self.is_running,
            "discovered_urls": len(self.discovered_urls),
            "analyzed_forms": len(self.analyzed_forms),
            "tested_injection_points": len(self.tested_injection_points),
            "vulnerabilities_found": len(self.scan_result.vulnerabilities),
            "current_phase": self._get_current_phase(),
        }
    
    def _get_current_phase(self) -> str:
        """Determine current scanning phase."""
        if not self.is_running:
            return "idle"
        elif len(self.discovered_urls) == 0:
            return "discovery"
        elif len(self.analyzed_forms) < len(self.discovered_urls):
            return "analysis"
        elif self.scan_result.statistics.payloads_tested < self.scan_result.statistics.injection_points_tested:
            return "injection"
        else:
            return "correlation"
    
    def _get_config_summary(self) -> Dict[str, any]:
        """Get configuration summary for reporting."""
        return {
            "target_url": self.config.target_url,
            "scan_intensity": self.config.scanning.intensity,
            "engines_enabled": self.config.scanning.engines,
            "crawl_depth": self.config.crawling.depth_limit,
            "safe_mode": self.config.safe_mode,
            "scanner_version": "1.0.0",
        }
    
    async def __aenter__(self):
        """Async context manager entry."""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.is_running:
            self.stop_scan()
        await self.http_client.close()
