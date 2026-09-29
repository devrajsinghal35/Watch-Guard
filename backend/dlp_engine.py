import re

class DLPEngine:
    def __init__(self):
        # Regex patterns for sensitive data
        self.patterns = {
            "CREDIT_CARD": re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})\b'),
            "SSN": re.compile(r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b'),
            "API_KEY": re.compile(r'(?i)(?:key|token|secret|password|bearer)[\s=:>]+["\']?([a-zA-Z0-9_\-\.]{20,})["\']?'),
            "INTERNAL_HEADER": re.compile(r'(?i)X-Honeywell-Internal-Key')
        }

    def scan_payload(self, payload: str) -> list:
        """
        Scans a given string payload for DLP violations.
        Returns a list of violation dictionaries.
        """
        violations = []
        if not payload:
            return violations

        for category, pattern in self.patterns.items():
            matches = pattern.finditer(payload)
            for match in matches:
                matched_string = match.group(0)
                # Redact the matched string for logging
                if category == "CREDIT_CARD":
                    redacted = f"XXXX-XXXX-XXXX-{matched_string[-4:]}"
                elif category == "SSN":
                    redacted = f"XXX-XX-{matched_string[-4:]}"
                elif category == "API_KEY":
                    redacted = f"{matched_string[:8]}...[REDACTED]"
                else:
                    redacted = "[REDACTED_INTERNAL_DATA]"

                violations.append({
                    "category": category,
                    "redacted_match": redacted
                })

        return violations

dlp_engine = DLPEngine()
