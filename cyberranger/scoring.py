import re
from typing import Any, Optional


# SQLi signature patterns in responses
SQLI_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning: mysql_",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"sqlstate\[",
    r"sqlite3::query",
    r"pg_query\(\)",
]

# Command injection signatures
CMD_OUTPUT_PATTERNS = [
    r"uid=\d+\([a-zA-Z0-9_\-]+\)\s+gid=\d+",
    r"root:[x*]:0:0:",
    r"Linux [a-zA-Z0-9_.\-]+",
    r"Microsoft Windows \[Version",
    r"www-data",
]

# Path traversal signatures
PATH_TRAVERSAL_PATTERNS = [
    r"root:.*:0:0:",
    r"\[extensions\]",
    r"\[fonts\]",
    r"daemon:x:\d+:\d+:",
    r"127\.0\.0\.1\s+localhost",
]


def score_target_compromise(response_text: str, status_code: int = 200, payload: str = "") -> tuple[bool, float]:
    """Heuristics: DB error strings, unexpected row counts, reflected script tags
    rendered unescaped, command output patterns, file contents leaking.
    
    Returns:
        (compromised: bool, confidence: float)
    """
    text_lower = response_text.lower()

    # 1. SQL injection error signatures
    for pattern in SQLI_ERROR_PATTERNS:
        if re.search(pattern, text_lower):
            return True, 0.95

    # 1b. Multi-row dump signatures (DVWA SQLi extracts multiple records)
    if "first name:" in text_lower and text_lower.count("surname:") > 1:
        return True, 0.98

    # 2. Command injection signatures
    for pattern in CMD_OUTPUT_PATTERNS:
        if re.search(pattern, response_text):
            return True, 1.0

    # 3. Path traversal signatures
    for pattern in PATH_TRAVERSAL_PATTERNS:
        if re.search(pattern, response_text):
            return True, 1.0

    # 4. Reflected XSS heuristics (unescaped script tags or payload reflection)
    xss_tokens = ["<script>", "<script ", "alert(", "onerror=", "onload=", "onfocus="]
    if any(t in text_lower for t in xss_tokens):
        if payload and payload.lower() in text_lower:
            return True, 0.95
        return True, 0.75

    if payload and len(payload) > 5 and payload in response_text:
        # Reflected payload in 200 response without error
        if status_code == 200 and "error" not in text_lower:
            return True, 0.5

    return False, 0.0


def score_detection(detector_response: dict[str, Any]) -> tuple[bool, float, Optional[str]]:
    """Read blue-detector's own verdict + confidence + which rule/feature fired.
    
    Returns:
        (flagged: bool, confidence: float, rule_fired: Optional[str])
    """
    flagged = bool(detector_response.get("flagged", False))
    confidence = float(detector_response.get("confidence", 0.0))
    rule_fired = detector_response.get("rule_fired")
    return flagged, confidence, rule_fired


def combined_fitness(compromise_conf: float, evasion_conf: float) -> float:
    """A payload that compromises AND evades is highest fitness. One that compromises
    but gets flagged is still useful (tells you the detector needs a rule that's
    currently missing entirely). Suggested starting formula:
        fitness = compromise_conf * (0.5 + 0.5 * (1 - evasion_conf))
    """
    return float(compromise_conf) * (0.5 + 0.5 * (1.0 - float(evasion_conf)))
