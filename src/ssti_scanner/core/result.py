"""
Result management for SSTI Scanner.

This module handles scan results, vulnerabilities, and reporting data structures.
"""

from __future__ import annotations

import json
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field


class VulnerabilityLevel(str, Enum):
    """Vulnerability severity levels."""
    LOW = "low"
    MEDIUM = "medium" 
    HIGH = "high"
    CRITICAL = "critical"


class DetectionMethod(str, Enum):
    """Detection methods used to identify vulnerabilities."""
    MATHEMATICAL = "mathematical"
    ERROR_BASED = "error_based"
    TIME_BASED = "time_based"
    BLIND = "blind"
    OUT_OF_BAND = "out_of_band"
    TEMPLATE_SPECIFIC = "template_specific"


class InjectionPoint(BaseModel):
    """Represents an injection point in the application."""
    
    url: str = Field(..., description="URL where injection was attempted")
    method: str = Field(default="GET", description="HTTP method")
    parameter: str = Field(..., description="Parameter name")
    parameter_type: str = Field(..., description="Parameter type (query, form, header, cookie)")
    original_value: Optional[str] = Field(default=None, description="Original parameter value")
    injection_context: str = Field(default="unknown", description="Context of injection")


class PayloadInfo(BaseModel):
    """Information about the payload used."""
    
    payload: str = Field(..., description="The actual payload")
    payload_type: str = Field(..., description="Type of payload")
    template_engine: str = Field(..., description="Target template engine")
    expected_result: Optional[str] = Field(default=None, description="Expected result")
    encoding: Optional[str] = Field(default=None, description="Payload encoding used")


class ResponseInfo(BaseModel):
    """Information about the response received."""
    
    status_code: int = Field(..., description="HTTP status code")
    headers: Dict[str, str] = Field(default_factory=dict, description="Response headers")
    content_type: Optional[str] = Field(default=None, description="Content type")
    content_length: Optional[int] = Field(default=None, description="Content length")
    response_time: float = Field(..., description="Response time in seconds")
    response_body: Optional[str] = Field(default=None, description="Response body (truncated)")
    redirect_chain: List[str] = Field(default_factory=list, description="Redirect chain URLs")


class Evidence(BaseModel):
    """Evidence of successful injection."""
    
    evidence_type: str = Field(..., description="Type of evidence")
    evidence_data: str = Field(..., description="Evidence data")
    location: str = Field(..., description="Where evidence was found")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score")
    description: str = Field(..., description="Evidence description")


class Vulnerability(BaseModel):
    """Represents a discovered SSTI vulnerability."""
    
    id: str = Field(..., description="Unique vulnerability ID")
    title: str = Field(..., description="Vulnerability title")
    description: str = Field(..., description="Detailed description")
    severity: VulnerabilityLevel = Field(..., description="Vulnerability severity")
    template_engine: str = Field(..., description="Identified template engine")
    detection_method: DetectionMethod = Field(..., description="Detection method used")
    
    # Location information
    injection_point: InjectionPoint = Field(..., description="Injection point details")
    
    # Payload and response information
    payload_info: PayloadInfo = Field(..., description="Payload information")
    response_info: ResponseInfo = Field(..., description="Response information")
    
    # Evidence
    evidence: List[Evidence] = Field(default_factory=list, description="Evidence list")
    
    # Metadata
    discovered_at: datetime = Field(default_factory=datetime.now, description="Discovery timestamp")
    confidence_score: float = Field(..., ge=0.0, le=1.0, description="Overall confidence")
    false_positive_likelihood: float = Field(default=0.0, ge=0.0, le=1.0)
    
    # Exploitation information
    exploitable: bool = Field(default=False, description="Whether vulnerability is exploitable")
    impact_assessment: str = Field(default="", description="Impact assessment")
    remediation: str = Field(default="", description="Remediation recommendations")
    
    # Additional context
    context: Dict[str, Any] = Field(default_factory=dict, description="Additional context")
    
    def add_evidence(self, evidence_type: str, evidence_data: str, 
                    location: str, confidence: float, description: str) -> None:
        """Add evidence to the vulnerability."""
        evidence = Evidence(
            evidence_type=evidence_type,
            evidence_data=evidence_data,
            location=location,
            confidence=confidence,
            description=description
        )
        self.evidence.append(evidence)
    
    def get_risk_score(self) -> float:
        """Calculate risk score based on severity and confidence."""
        severity_weights = {
            VulnerabilityLevel.LOW: 0.25,
            VulnerabilityLevel.MEDIUM: 0.50,
            VulnerabilityLevel.HIGH: 0.75,
            VulnerabilityLevel.CRITICAL: 1.0
        }
        
        base_score = severity_weights.get(self.severity, 0.5)
        confidence_weight = self.confidence_score
        false_positive_penalty = self.false_positive_likelihood * 0.3
        
        return max(0.0, min(1.0, (base_score * confidence_weight) - false_positive_penalty))


class ScanStatistics(BaseModel):
    """Statistics for a scan session."""
    
    start_time: datetime = Field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    duration: Optional[float] = None
    
    # Target statistics
    urls_discovered: int = 0
    forms_analyzed: int = 0
    injection_points_tested: int = 0
    
    # Request statistics
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    
    # Payload statistics
    payloads_tested: int = 0
    unique_payloads: int = 0
    
    # Detection statistics
    vulnerabilities_found: int = 0
    false_positives: int = 0
    template_engines_detected: List[str] = Field(default_factory=list)
    
    def update_duration(self) -> None:
        """Update scan duration."""
        if self.end_time:
            self.duration = (self.end_time - self.start_time).total_seconds()


class ScanResult(BaseModel):
    """Complete scan result containing all findings and metadata."""
    
    scan_id: str = Field(..., description="Unique scan identifier")
    target_info: Dict[str, Any] = Field(default_factory=dict, description="Target information")
    config_summary: Dict[str, Any] = Field(default_factory=dict, description="Configuration summary")
    
    # Results
    vulnerabilities: List[Vulnerability] = Field(default_factory=list, description="Found vulnerabilities")
    statistics: ScanStatistics = Field(default_factory=ScanStatistics, description="Scan statistics")
    
    # Metadata
    scanner_version: str = Field(default="1.0.0", description="Scanner version")
    scan_type: str = Field(default="comprehensive", description="Type of scan performed")
    
    # State management
    completed: bool = Field(default=False, description="Whether scan completed successfully")
    error_messages: List[str] = Field(default_factory=list, description="Error messages")
    warnings: List[str] = Field(default_factory=list, description="Warning messages")
    
    def add_vulnerability(self, vulnerability: Vulnerability) -> None:
        """Add a vulnerability to the results."""
        self.vulnerabilities.append(vulnerability)
        self.statistics.vulnerabilities_found += 1
        
        # Update template engines detected
        if vulnerability.template_engine not in self.statistics.template_engines_detected:
            self.statistics.template_engines_detected.append(vulnerability.template_engine)
    
    def get_vulnerabilities_by_severity(self, severity: VulnerabilityLevel) -> List[Vulnerability]:
        """Get vulnerabilities filtered by severity."""
        return [vuln for vuln in self.vulnerabilities if vuln.severity == severity]
    
    def get_high_confidence_vulnerabilities(self, threshold: float = 0.8) -> List[Vulnerability]:
        """Get vulnerabilities with high confidence scores."""
        return [vuln for vuln in self.vulnerabilities if vuln.confidence_score >= threshold]
    
    def get_exploitable_vulnerabilities(self) -> List[Vulnerability]:
        """Get vulnerabilities marked as exploitable."""
        return [vuln for vuln in self.vulnerabilities if vuln.exploitable]
    
    def get_summary(self) -> Dict[str, Any]:
        """Get scan summary."""
        severity_counts = {
            "critical": len(self.get_vulnerabilities_by_severity(VulnerabilityLevel.CRITICAL)),
            "high": len(self.get_vulnerabilities_by_severity(VulnerabilityLevel.HIGH)),
            "medium": len(self.get_vulnerabilities_by_severity(VulnerabilityLevel.MEDIUM)),
            "low": len(self.get_vulnerabilities_by_severity(VulnerabilityLevel.LOW)),
        }
        
        return {
            "scan_id": self.scan_id,
            "completed": self.completed,
            "total_vulnerabilities": len(self.vulnerabilities),
            "high_confidence_vulnerabilities": len(self.get_high_confidence_vulnerabilities()),
            "exploitable_vulnerabilities": len(self.get_exploitable_vulnerabilities()),
            "severity_breakdown": severity_counts,
            "template_engines_detected": self.statistics.template_engines_detected,
            "scan_duration": self.statistics.duration,
            "urls_tested": self.statistics.urls_discovered,
            "injection_points_tested": self.statistics.injection_points_tested,
        }
    
    def finalize_scan(self) -> None:
        """Finalize the scan and update statistics."""
        self.completed = True
        self.statistics.end_time = datetime.now()
        self.statistics.update_duration()
    
    def to_json(self, indent: int = 2) -> str:
        """Convert result to JSON string."""
        return self.json(indent=indent, ensure_ascii=False)
    
    def save_to_file(self, file_path: Union[str, Path], format_type: str = "json") -> None:
        """Save results to file in specified format."""
        file_path = Path(file_path)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        if format_type.lower() == "json":
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(self.to_json())
        else:
            raise ValueError(f"Unsupported format: {format_type}")
    
    @classmethod
    def load_from_file(cls, file_path: Union[str, Path]) -> ScanResult:
        """Load results from JSON file."""
        file_path = Path(file_path)
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return cls(**data)
