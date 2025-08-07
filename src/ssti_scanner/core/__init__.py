"""Core module initialization."""

from .config import Config
from .result import ScanResult, Vulnerability
from .scanner import SSTIScanner
from .engine_manager import EngineManager
from .form_analyzer import FormAnalyzer
from .result_correlator import ResultCorrelator

__all__ = [
    "Config", 
    "ScanResult", 
    "Vulnerability", 
    "SSTIScanner",
    "EngineManager",
    "FormAnalyzer", 
    "ResultCorrelator"
]
