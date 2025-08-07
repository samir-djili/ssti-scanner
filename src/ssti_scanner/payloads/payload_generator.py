"""Payload generator for SSTI Scanner."""

class PayloadGenerator:
    """Generate payloads dynamically based on context and engine."""
    
    def __init__(self):
        pass
    
    def generate_math_payloads(self, engine_name: str) -> list:
        """Generate mathematical expression payloads."""
        return ["{{7*7}}", "${7*7}", "{7*7}"]
    
    def generate_config_payloads(self, engine_name: str) -> list:
        """Generate configuration disclosure payloads."""
        return ["{{config}}", "${config}", "{config}"]
