"""CSV reporter for SSTI Scanner."""
from .base_reporter import BaseReporter
class CSVReporter(BaseReporter):
    def generate_report(self, scan_result): return "URL,Engine,Confidence,Type,Payload\n"
    def get_file_extension(self): return "csv"
