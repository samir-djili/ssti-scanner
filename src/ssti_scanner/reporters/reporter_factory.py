"""Reporter factory for SSTI Scanner."""

from typing import Optional
from .base_reporter import BaseReporter
from .console_reporter import ConsoleReporter
from .json_reporter import JSONReporter
from .html_reporter import HTMLReporter
from .csv_reporter import CSVReporter
from .xml_reporter import XMLReporter

class ReporterFactory:
    """Factory for creating reporter instances."""
    
    _reporters = {
        'console': ConsoleReporter,
        'json': JSONReporter,
        'html': HTMLReporter,
        'csv': CSVReporter,
        'xml': XMLReporter,
    }
    
    @classmethod
    def create_reporter(cls, format_name: str, output_file: str = None) -> Optional[BaseReporter]:
        """Create reporter instance by format name."""
        reporter_class = cls._reporters.get(format_name.lower())
        if reporter_class:
            return reporter_class(output_file)
        return None
    
    @classmethod
    def get_available_formats(cls) -> list:
        """Get list of available report formats."""
        return list(cls._reporters.keys())
