"""Tests for scoring and fitness computation (§7)."""

import pytest

from cyberranger.scoring import combined_fitness, score_detection, score_target_compromise


def test_score_target_compromise_heuristics():
    """Verify response-diff heuristics detect SQLi, Command Injection, XSS, and Traversal."""
    # 1. SQLi Error
    sqli_resp = "<html>Warning: mysql_fetch_array() expects parameter 1 to be resource</html>"
    comp, conf = score_target_compromise(sqli_resp)
    assert comp is True
    assert conf >= 0.9

    # 2. Command Injection
    cmd_resp = "Linux cyberranger-box 6.1.0 #1 SMP uid=33(www-data) gid=33(www-data)"
    comp, conf = score_target_compromise(cmd_resp)
    assert comp is True
    assert conf == 1.0

    # 3. Path Traversal
    passwd_resp = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
    comp, conf = score_target_compromise(passwd_resp)
    assert comp is True
    assert conf == 1.0

    # 4. Reflected XSS
    xss_payload = "<script>alert('xss')</script>"
    xss_resp = f"<div>Hello {xss_payload}</div>"
    comp, conf = score_target_compromise(xss_resp, payload=xss_payload)
    assert comp is True
    assert conf >= 0.9

    # 5. Clean / Benign response
    clean_resp = "<html><body>Welcome to our website! All systems operational.</body></html>"
    comp, conf = score_target_compromise(clean_resp)
    assert comp is False
    assert conf == 0.0


def test_score_detection_parsing():
    """Verify detector response parsing extracts flags and fired rules."""
    det_resp = {
        "flagged": True,
        "confidence": 0.88,
        "rule_fired": "rule_special_char_count",
    }
    flagged, conf, rule = score_detection(det_resp)
    assert flagged is True
    assert conf == 0.88
    assert rule == "rule_special_char_count"


def test_combined_fitness_formula():
    """Verify fitness calculation: highest when compromised AND evasive (§7)."""
    # Compromised (conf=1.0) and completely undetected (evasion_conf=0.0) -> fitness 1.0
    f_perfect = combined_fitness(compromise_conf=1.0, evasion_conf=0.0)
    assert f_perfect == 1.0

    # Compromised (conf=1.0) but fully flagged (evasion_conf=1.0) -> fitness 0.5
    f_flagged = combined_fitness(compromise_conf=1.0, evasion_conf=1.0)
    assert f_flagged == 0.5

    # Not compromised (conf=0.0) -> fitness 0.0 regardless of evasion
    f_failed = combined_fitness(compromise_conf=0.0, evasion_conf=0.0)
    assert f_failed == 0.0
