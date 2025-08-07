"""XML reporter for SSTI Scanner."""
from .base_reporter import BaseReporter
class XMLReporter(BaseReporter):
    def generate_report(self, scan_result): return "<?xml version='1.0'?><report></report>"
    def get_file_extension(self): return "xml"
