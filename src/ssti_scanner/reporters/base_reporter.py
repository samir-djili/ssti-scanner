"""
Base reporter class for SSTI Scanner output.

This module defines the abstract base class for all report generators.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List
from pathlib import Path

from ssti_scanner.core.result import ScanResult


class BaseReporter(ABC):
    """Abstract base class for report generators."""
    
    def __init__(self, output_file: str = None):
        """
        Initialize reporter.
        
        Args:
            output_file: Optional output file path
        """
        self.output_file = output_file
    
    @abstractmethod
    def generate_report(self, scan_result: ScanResult) -> str:
        """
        Generate report from scan results.
        
        Args:
            scan_result: Results of the SSTI scan
            
        Returns:
            Generated report as string
        """
        pass
    
    @abstractmethod
    def get_file_extension(self) -> str:
        """Get the file extension for this report format."""
        pass
    
    def save_report(self, scan_result: ScanResult, output_path: str = None) -> str:
        """
        Save report to file.
        
        Args:
            scan_result: Results of the SSTI scan
            output_path: Optional output path, uses default if None
            
        Returns:
            Path where report was saved
        """
        report_content = self.generate_report(scan_result)
        
        if not output_path:
            if self.output_file:
                output_path = self.output_file
            else:
                # Generate default filename
                timestamp = scan_result.metadata.get('timestamp', 'unknown')
                extension = self.get_file_extension()
                output_path = f"ssti_scan_report_{timestamp}.{extension}"
        
        # Ensure directory exists
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        
        # Write report
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        return output_path
    
    def _format_vulnerability_summary(self, scan_result: ScanResult) -> Dict[str, Any]:
        """Generate vulnerability summary statistics."""
        total_vulns = len(scan_result.vulnerabilities)
        
        # Count by confidence level
        confidence_counts = {
            'confirmed': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
        
        # Count by vulnerability type
        type_counts = {}
        
        # Count by engine
        engine_counts = {}
        
        for vuln in scan_result.vulnerabilities:
            # Confidence counts
            confidence_counts[vuln.confidence.value] = confidence_counts.get(vuln.confidence.value, 0) + 1
            
            # Type counts
            type_counts[vuln.vulnerability_type.value] = type_counts.get(vuln.vulnerability_type.value, 0) + 1
            
            # Engine counts
            engine_counts[vuln.engine_name] = engine_counts.get(vuln.engine_name, 0) + 1
        
        return {
            'total_vulnerabilities': total_vulns,
            'confidence_distribution': confidence_counts,
            'vulnerability_types': type_counts,
            'affected_engines': engine_counts,
            'unique_endpoints': len(set(vuln.url for vuln in scan_result.vulnerabilities)),
            'scan_duration': scan_result.metadata.get('duration', 0),
            'requests_made': scan_result.metadata.get('total_requests', 0),
            'success_rate': scan_result.metadata.get('success_rate', 0.0)
        }
    
    def _get_severity_score(self, vulnerability) -> int:
        """Calculate severity score for vulnerability sorting."""
        confidence_scores = {
            'confirmed': 100,
            'high': 75,
            'medium': 50,
            'low': 25
        }
        
        type_scores = {
            'code_execution': 40,
            'file_access': 30,
            'information_disclosure': 20,
            'blind_injection': 10
        }
        
        confidence_score = confidence_scores.get(vulnerability.confidence.value, 0)
        type_score = type_scores.get(vulnerability.vulnerability_type.value, 0)
        
        return confidence_score + type_score
