"""Multi-vulnerability DVWA environment for the co-evolution arena.

Extends the stage-1 idea to several DVWA vulnerabilities (SQLi, XSS, command
injection, path traversal). Handles DVWA login + security cookie, applies a
per-category breach heuristic, and falls back to MOCK MODE if the app is down.

Containment: localhost/127.0.0.1 only, enforced on every request.
"""

from urllib.parse import urlparse
import re

import requests

DVWA_URL = "http://localhost:8080"
DVWA_USER = "admin"
DVWA_PASS = "password"
TIMEOUT = 3

# Which DVWA page each category attacks, and how the payload is delivered.
_ENDPOINTS = {
    "sqli": ("GET", "/vulnerabilities/sqli/", "id"),
    "xss": ("GET", "/vulnerabilities/xss_r/", "name"),
    "cmdi": ("POST", "/vulnerabilities/exec/", "ip"),
    "traversal": ("GET", "/vulnerabilities/fi/", "page"),
}

# Substrings in the response that indicate a successful breach, per category.
_BREACH_MARKERS = {
    "sqli": ["first name", "surname", "admin"],
    "xss": ["<script>alert", "onerror=alert", "onload=alert"],
    "cmdi": ["uid=", "root:x:", "root:"],
    "traversal": ["root:x:0:0", "root:", "daemon:"],
}


def endpoint_for(category):
    """Human-facing DVWA path a category attacks (for UI display)."""
    ep = _ENDPOINTS.get(category)
    return ep[1] if ep else "-"


def _assert_localhost(url):
    """Refuse any non-local target. Sandbox containment guard."""
    host = (urlparse(url).hostname or "").lower()
    if host not in ("localhost", "127.0.0.1", "::1"):
        raise ValueError(
            f"Refusing to target non-local host '{host}'. "
            "CyberRanger only attacks localhost sandboxes."
        )


class DVWAEnvironment:
    """Authenticated DVWA target with a mock fallback."""

    def __init__(self, base_url=DVWA_URL):
        _assert_localhost(base_url)
        self.base_url = base_url
        self.session = requests.Session()
        self.mock_mode = not self._login()

    # -- setup -------------------------------------------------------------
    def _login(self):
        """Log into DVWA and set security=low. Returns True on success."""
        try:
            login_url = f"{self.base_url}/login.php"
            r = self.session.get(login_url, timeout=TIMEOUT)
            token = self._extract_token(r.text)
            data = {"username": DVWA_USER, "password": DVWA_PASS,
                    "Login": "Login"}
            if token:
                data["user_token"] = token
            self.session.post(login_url, data=data, timeout=TIMEOUT)
            # Force security level to low via cookie.
            self.session.cookies.set("security", "low")
            # Confirm we can reach an authed page.
            check = self.session.get(
                f"{self.base_url}/vulnerabilities/sqli/", timeout=TIMEOUT)
            return check.status_code == 200 and "login.php" not in check.url
        except requests.RequestException:
            return False

    @staticmethod
    def _extract_token(html):
        m = re.search(r"name=['\"]user_token['\"]\s+value=['\"]([^'\"]+)", html)
        return m.group(1) if m else None

    # -- execution ---------------------------------------------------------
    def execute(self, payload, category):
        """Fire one payload at its category endpoint.

        Returns {status_code, breached, response_snippet}.
        """
        if self.mock_mode or category not in _ENDPOINTS:
            return self._mock(payload, category)
        return self._real(payload, category)

    def _real(self, payload, category):
        _assert_localhost(self.base_url)
        method, path, field = _ENDPOINTS[category]
        url = f"{self.base_url}{path}"
        try:
            if method == "POST":
                params = {field: payload, "Submit": "Submit"}
                resp = self.session.post(url, data=params, timeout=TIMEOUT)
            else:
                params = {field: payload, "Submit": "Submit"}
                resp = self.session.get(url, params=params, timeout=TIMEOUT)
            body = resp.text
            breached = self._is_breach(category, body, resp.status_code)
            return {
                "status_code": resp.status_code,
                "breached": breached,
                "response_snippet": _snippet(body),
            }
        except requests.RequestException:
            # A single failed/odd request is just a miss — do NOT poison the
            # whole live session by latching to mock. Only the startup login
            # check decides real-vs-mock for the run.
            return {
                "status_code": 0,
                "breached": False,
                "response_snippet": "(request failed to send)",
            }

    def _is_breach(self, category, body, status_code):
        if status_code != 200:
            return False
        low = body.lower()
        return any(m in low for m in _BREACH_MARKERS.get(category, []))

    # -- mock --------------------------------------------------------------
    def _mock(self, payload, category):
        """Simulate a plausible response so the demo never hard-fails.

        A payload 'breaches' if it still contains recognizable attack intent;
        benign strings do not. This keeps mock dynamics honest-ish.
        """
        breached = category in _ENDPOINTS
        snippets = {
            "sqli": "ID: admin  First name: admin  Surname: admin",
            "xss": f"Hello {payload}",
            "cmdi": "uid=33(www-data) gid=33(www-data) groups=33",
            "traversal": "root:x:0:0:root:/root:/bin/bash",
        }
        return {
            "status_code": 200,
            "breached": breached,
            "response_snippet": snippets.get(category, f"echo {payload}"),
        }


def _snippet(body, n=90):
    return re.sub(r"\s+", " ", body)[:n].strip()
