import math
import re
from typing import Any


FEATURE_NAMES = [
    "length",
    "special_char_count",
    "special_char_ratio",
    "digit_ratio",
    "uppercase_ratio",
    "has_sql_keywords",
    "has_xss_keywords",
    "has_cmd_keywords",
    "has_traversal_markers",
    "has_encoding_markers",
    "comment_markers_count",
    "shannon_entropy",
]


def compute_entropy(text: str) -> float:
    if not text:
        return 0.0
    prob_map = {}
    for c in text:
        prob_map[c] = prob_map.get(c, 0) + 1
    entropy = 0.0
    for count in prob_map.values():
        p = count / len(text)
        entropy -= p * math.log2(p)
    return entropy


def extract_text_from_request(req_payload: dict[str, Any] | str) -> str:
    """Normalize input into an analyzable string."""
    if isinstance(req_payload, str):
        return req_payload
    parts = []
    if "url" in req_payload:
        parts.append(str(req_payload["url"]))
    if "params" in req_payload and isinstance(req_payload["params"], dict):
        for k, v in req_payload["params"].items():
            parts.append(f"{k}={v}")
    if "body" in req_payload and req_payload["body"]:
        parts.append(str(req_payload["body"]))
    return " ".join(parts)


def extract_features(input_data: dict[str, Any] | str) -> list[float]:
    """Extract structural, syntactic, and statistical generalization features (§10)."""
    text = extract_text_from_request(input_data)
    text_lower = text.lower()
    length = float(len(text))

    if length == 0:
        return [0.0] * len(FEATURE_NAMES)

    special_chars = set("'\"`<>;&|/\\#*()=-+$%!")
    special_count = sum(1 for c in text if c in special_chars)
    special_ratio = special_count / length
    digit_ratio = sum(1 for c in text if c.isdigit()) / length
    uppercase_ratio = sum(1 for c in text if c.isupper()) / length

    # Domain keyword markers
    has_sql = 1.0 if re.search(r"\b(select|union|insert|drop|or|and|from|where)\b", text_lower) else 0.0
    has_xss = 1.0 if re.search(r"(<script|alert\(|onerror=|onload=|<img|javascript:)", text_lower) else 0.0
    has_cmd = 1.0 if re.search(r"\b(whoami|cat\s+|/bin/|passwd|uname|sudo|id\b)", text_lower) else 0.0
    has_traversal = 1.0 if ("../" in text or "..\\" in text or "%2e%2e" in text_lower) else 0.0
    has_encoding = 1.0 if ("%" in text or "0x" in text_lower or "\\u" in text_lower) else 0.0
    comment_markers = float(text.count("/**/") + text.count("--") + text.count("#"))

    entropy = compute_entropy(text)

    return [
        min(length / 200.0, 5.0),  # normalized length
        float(special_count),
        special_ratio,
        digit_ratio,
        uppercase_ratio,
        has_sql,
        has_xss,
        has_cmd,
        has_traversal,
        has_encoding,
        comment_markers,
        entropy,
    ]
