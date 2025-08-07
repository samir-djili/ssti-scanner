"""
Console reporter for SSTI Scanner.

This module provides colored console output for scan results.
"""

import sys
from typing import Dict, Any
from datetime import datetime

from .base_reporter import BaseReporter
from ssti_scanner.core.result import ScanResult


class Colors:
    """ANSI color codes for console output."""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'
    
    @classmethod
    def disable(cls):
        """Disable colors for non-TTY output."""
        cls.RED = cls.GREEN = cls.YELLOW = cls.BLUE = ''
        cls.MAGENTA = cls.CYAN = cls.WHITE = cls.BOLD = ''
        cls.UNDERLINE = cls.END = ''


class ConsoleReporter(BaseReporter):
    """Console reporter with colored output."""
    
    def __init__(self, use_colors: bool = None):
        """
        Initialize console reporter.
        
        Args:
            use_colors: Enable/disable colors, auto-detect if None
        """
        super().__init__()
        
        if use_colors is None:
            use_colors = sys.stdout.isatty()
        
        if not use_colors:
            Colors.disable()
    
    def generate_report(self, scan_result: ScanResult) -> str:
        """Generate console report."""
        lines = []
        
        # Header
        lines.append(self._generate_header(scan_result))
        lines.append("")
        
        # Summary
        lines.append(self._generate_summary(scan_result))
        lines.append("")
        
        # Vulnerabilities
        if scan_result.vulnerabilities:
            lines.append(self._generate_vulnerabilities_section(scan_result))
            lines.append("")
        
        # Statistics
        lines.append(self._generate_statistics(scan_result))
        lines.append("")
        
        # Footer
        lines.append(self._generate_footer())
        
        return "\n".join(lines)
    
    def get_file_extension(self) -> str:
        """Get file extension for console output."""
        return "txt"
    
    def _generate_header(self, scan_result: ScanResult) -> str:
        """Generate report header."""
        lines = [
            f"{Colors.BOLD}{Colors.CYAN}{'='*80}{Colors.END}",
            f"{Colors.BOLD}{Colors.CYAN}                    SSTI Scanner Report{Colors.END}",
            f"{Colors.BOLD}{Colors.CYAN}{'='*80}{Colors.END}",
            "",
            f"{Colors.BOLD}Target:{Colors.END} {scan_result.target_url}",
            f"{Colors.BOLD}Scan Date:{Colors.END} {scan_result.metadata.get('timestamp', 'Unknown')}",
            f"{Colors.BOLD}Scanner Version:{Colors.END} {scan_result.metadata.get('version', '1.0.0')}",
        ]
        
        return "\n".join(lines)
    
    def _generate_summary(self, scan_result: ScanResult) -> str:
        """Generate scan summary."""
        summary = self._format_vulnerability_summary(scan_result)
        
        lines = [
            f"{Colors.BOLD}{Colors.YELLOW}SCAN SUMMARY{Colors.END}",
            f"{Colors.BOLD}{'-'*40}{Colors.END}",
        ]
        
        # Vulnerability counts with colors
        total = summary['total_vulnerabilities']
        if total == 0:
            color = Colors.GREEN
            status = "No vulnerabilities found"
        elif summary['confidence_distribution']['confirmed'] > 0:
            color = Colors.RED
            status = f"{total} vulnerabilities found (CRITICAL)"
        elif summary['confidence_distribution']['high'] > 0:
            color = Colors.RED
            status = f"{total} vulnerabilities found (HIGH RISK)"
        else:
            color = Colors.YELLOW
            status = f"{total} vulnerabilities found"
        
        lines.append(f"{Colors.BOLD}Status:{Colors.END} {color}{status}{Colors.END}")
        
        if total > 0:
            lines.extend([
                f"{Colors.BOLD}Breakdown:{Colors.END}",
                f"  • Confirmed: {Colors.RED}{summary['confidence_distribution']['confirmed']}{Colors.END}",
                f"  • High: {Colors.RED}{summary['confidence_distribution']['high']}{Colors.END}",
                f"  • Medium: {Colors.YELLOW}{summary['confidence_distribution']['medium']}{Colors.END}",
                f"  • Low: {Colors.GREEN}{summary['confidence_distribution']['low']}{Colors.END}",
                "",
                f"{Colors.BOLD}Affected Endpoints:{Colors.END} {summary['unique_endpoints']}",
                f"{Colors.BOLD}Template Engines:{Colors.END} {', '.join(summary['affected_engines'].keys()) if summary['affected_engines'] else 'None detected'}",
            ])
        
        lines.extend([
            "",
            f"{Colors.BOLD}Scan Statistics:{Colors.END}",
            f"  • Duration: {summary['scan_duration']:.2f} seconds",
            f"  • Requests Made: {summary['requests_made']}",
            f"  • Success Rate: {summary['success_rate']:.1%}",
        ])
        
        return "\n".join(lines)
    
    def _generate_vulnerabilities_section(self, scan_result: ScanResult) -> str:
        """Generate vulnerabilities section."""
        lines = [
            f"{Colors.BOLD}{Colors.RED}VULNERABILITIES FOUND{Colors.END}",
            f"{Colors.BOLD}{'-'*50}{Colors.END}",
            ""
        ]
        
        # Sort vulnerabilities by severity
        sorted_vulns = sorted(
            scan_result.vulnerabilities,
            key=self._get_severity_score,
            reverse=True
        )
        
        for i, vuln in enumerate(sorted_vulns, 1):
            lines.extend(self._format_vulnerability(i, vuln))
            lines.append("")
        
        return "\n".join(lines)
    
    def _format_vulnerability(self, index: int, vulnerability) -> list:
        """Format individual vulnerability."""
        # Confidence color mapping
        confidence_colors = {
            'confirmed': Colors.RED,
            'high': Colors.RED,
            'medium': Colors.YELLOW,
            'low': Colors.GREEN
        }
        
        color = confidence_colors.get(vulnerability.confidence.value, Colors.WHITE)
        
        lines = [
            f"{Colors.BOLD}[{index}] {color}{vulnerability.confidence.value.upper()} CONFIDENCE{Colors.END}",
            f"{Colors.BOLD}URL:{Colors.END} {vulnerability.url}",
            f"{Colors.BOLD}Engine:{Colors.END} {vulnerability.engine_name}",
            f"{Colors.BOLD}Type:{Colors.END} {vulnerability.vulnerability_type.value}",
            f"{Colors.BOLD}Payload:{Colors.END} {vulnerability.payload}",
        ]
        
        if vulnerability.description:
            lines.append(f"{Colors.BOLD}Description:{Colors.END} {vulnerability.description}")
        
        if vulnerability.evidence:
            lines.append(f"{Colors.BOLD}Evidence:{Colors.END} {vulnerability.evidence}")
        
        if vulnerability.impact:
            lines.append(f"{Colors.BOLD}Impact:{Colors.END} {Colors.RED}{vulnerability.impact}{Colors.END}")
        
        if vulnerability.remediation:
            lines.append(f"{Colors.BOLD}Remediation:{Colors.END} {vulnerability.remediation}")
        
        if vulnerability.metadata:
            lines.append(f"{Colors.BOLD}Additional Info:{Colors.END}")
            for key, value in vulnerability.metadata.items():
                lines.append(f"  • {key}: {value}")
        
        return lines
    
    def _generate_statistics(self, scan_result: ScanResult) -> str:
        """Generate detailed statistics."""
        lines = [
            f"{Colors.BOLD}{Colors.BLUE}DETAILED STATISTICS{Colors.END}",
            f"{Colors.BOLD}{'-'*40}{Colors.END}",
        ]
        
        # Add crawling statistics if available
        crawl_stats = scan_result.metadata.get('crawling_stats', {})
        if crawl_stats:
            lines.extend([
                f"{Colors.BOLD}Crawling:{Colors.END}",
                f"  • Pages Discovered: {crawl_stats.get('pages_found', 0)}",
                f"  • Forms Analyzed: {crawl_stats.get('forms_found', 0)}",
                f"  • Parameters Found: {crawl_stats.get('parameters_found', 0)}",
                ""
            ])
        
        # Add detection statistics
        detection_stats = scan_result.metadata.get('detection_stats', {})
        if detection_stats:
            lines.extend([
                f"{Colors.BOLD}Detection:{Colors.END}",
                f"  • Payloads Tested: {detection_stats.get('payloads_tested', 0)}",
                f"  • Template Engines Tested: {detection_stats.get('engines_tested', 0)}",
                f"  • Contexts Analyzed: {detection_stats.get('contexts_analyzed', 0)}",
                ""
            ])
        
        return "\n".join(lines)
    
    def _generate_footer(self) -> str:
        """Generate report footer."""
        return f"{Colors.BOLD}{Colors.CYAN}{'='*80}{Colors.END}"
    
    def print_progress(self, message: str, level: str = "info") -> None:
        """Print progress message with appropriate color."""
        color_map = {
            'info': Colors.BLUE,
            'success': Colors.GREEN,
            'warning': Colors.YELLOW,
            'error': Colors.RED,
            'debug': Colors.MAGENTA
        }
        
        color = color_map.get(level, Colors.WHITE)
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        print(f"{Colors.BOLD}[{timestamp}]{Colors.END} {color}{message}{Colors.END}")
    
    def print_vulnerability_found(self, vulnerability) -> None:
        """Print immediate notification of vulnerability found."""
        confidence_colors = {
            'confirmed': Colors.RED,
            'high': Colors.RED,
            'medium': Colors.YELLOW,
            'low': Colors.GREEN
        }
        
        color = confidence_colors.get(vulnerability.confidence.value, Colors.WHITE)
        
        print(f"\n{Colors.BOLD}{color}🚨 VULNERABILITY FOUND!{Colors.END}")
        print(f"{Colors.BOLD}Engine:{Colors.END} {vulnerability.engine_name}")
        print(f"{Colors.BOLD}Confidence:{Colors.END} {color}{vulnerability.confidence.value.upper()}{Colors.END}")
        print(f"{Colors.BOLD}URL:{Colors.END} {vulnerability.url}")
        print(f"{Colors.BOLD}Payload:{Colors.END} {vulnerability.payload}\n")
