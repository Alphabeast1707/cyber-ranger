"""Blue team agent for CyberRanger Arena.

Inspects an outgoing request and decides whether it looks malicious, using
a small regex ruleset. In stage 1 this is pure pattern matching; later
stages swap detect() for LLM-based reasoning.
"""

import re


class BlueAgent:
    """Regex-based intrusion detector for SQLi and XSS payloads."""

    def __init__(self):
        # Deliberately small and readable. Case-insensitive.
        self._sqli_patterns = [
            r"'\s*or\s*'?\d*'?\s*=\s*'?\d*",   # ' OR '1'='1
            r"\bunion\b.*\bselect\b",          # UNION SELECT
            r"--\s*",                          # SQL comment
            r";\s*drop\s+table",               # stacked DROP
        ]
        self._xss_patterns = [
            r"<\s*script",                     # <script
            r"on\w+\s*=",                      # onerror=, onload=
            r"javascript:",                    # javascript: URI
            r"<\s*img[^>]*\bsrc\b",            # <img src=...
        ]
        self._rules = [re.compile(p, re.IGNORECASE)
                       for p in self._sqli_patterns + self._xss_patterns]

    def detect(self, request):
        """Return True if the request's payload matches any attack rule.

        request is the action dict emitted by RedAgent; we inspect its
        'payload' field.
        """
        # LLM reasoning plugs in here: replace the regex sweep below with an
        # LLM that reasons about intent given the full request context.
        payload = str(request.get("payload", ""))
        return any(rule.search(payload) for rule in self._rules)
