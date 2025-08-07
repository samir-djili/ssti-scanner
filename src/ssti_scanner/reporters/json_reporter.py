"""JSON reporter for SSTI Scanner."""

import json
from datetime import datetime
from .base_reporter import BaseReporter
from ssti_scanner.core.result import ScanResult

class JSONReporter(BaseReporter):
    """JSON format reporter."""
    
    def __init__(self, output_file: str = None):
        super().__init__(output_file)
    
    def generate_report(self, scan_result: ScanResult) -> str:
        """Generate JSON report."""
        report_data = {
            "scan_info": {
                "target_url": scan_result.target_url,
                "timestamp": scan_result.metadata.get('timestamp', datetime.now().isoformat()),
                "version": scan_result.metadata.get('version', '1.0.0'),
                "duration": scan_result.metadata.get('duration', 0)
            },
            "summary": self._format_vulnerability_summary(scan_result),
            "vulnerabilities": [self._format_vulnerability_json(vuln) for vuln in scan_result.vulnerabilities],
            "metadata": scan_result.metadata
        }
        
        return json.dumps(report_data, indent=2, ensure_ascii=False)
    
    def get_file_extension(self) -> str:
        """Get file extension."""
        return "json"
    
    def _format_vulnerability_json(self, vulnerability) -> dict:
        """Format vulnerability for JSON output."""
        return {
            "url": vulnerability.url,
            "engine_name": vulnerability.engine_name,
            "confidence": vulnerability.confidence.value,
            "vulnerability_type": vulnerability.vulnerability_type.value,
            "payload": vulnerability.payload,
            "evidence": vulnerability.evidence,
            "description": vulnerability.description,
            "impact": vulnerability.impact,
            "remediation": vulnerability.remediation,
            "metadata": vulnerability.metadata or {}
        }
