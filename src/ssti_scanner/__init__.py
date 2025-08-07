"""
SSTI Scanner - A sophisticated, modular Python-based Server-Side Template Injection vulnerability scanner.

This package provides comprehensive detection capabilities across multiple template engines
with an intuitive command-line interface designed for security professionals and penetration testers.
"""

__version__ = "1.0.0"
__author__ = "Samir Djili"
__email__ = "samir.djili@example.com"
__license__ = "MIT"

from ssti_scanner.core.scanner import SSTIScanner
from ssti_scanner.core.config import Config
from ssti_scanner.core.result import ScanResult, Vulnerability

__all__ = [
    "SSTIScanner",
    "Config", 
    "ScanResult",
    "Vulnerability",
    "__version__",
]
