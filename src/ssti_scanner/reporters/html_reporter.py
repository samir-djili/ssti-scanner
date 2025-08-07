"""HTML reporter for SSTI Scanner."""
from .base_reporter import BaseReporter
class HTMLReporter(BaseReporter):
    def generate_report(self, scan_result): return "<html>HTML Report Placeholder</html>"
    def get_file_extension(self): return "html"
