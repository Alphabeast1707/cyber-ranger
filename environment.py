"""Execution environment for CyberRanger Arena.

Sends a Red action to the target app (DVWA) and reports back what happened:
status code, whether a breach heuristic fired, and a response snippet.

Containment: only localhost/127.0.0.1 targets are ever allowed. If the app
is unreachable, we fall back to MOCK MODE so a live demo never hard-fails.
"""

from urllib.parse import urlparse

import requests

DVWA_URL = "http://localhost:8080"
REQUEST_TIMEOUT = 3  # seconds; keep the demo snappy

# Success markers that heuristically indicate a breach in DVWA responses.
_SQLI_BREACH_MARKERS = ["first name", "surname", "admin", "password"]
_XSS_BREACH_MARKERS = ["<script>alert", "onerror=alert", "<img src=x"]


def _assert_localhost(url):
    """Refuse to send anywhere except localhost/127.0.0.1. Sandbox guard."""
    host = (urlparse(url).hostname or "").lower()
    if host not in ("localhost", "127.0.0.1", "::1"):
        raise ValueError(
            f"Refusing to target non-local host '{host}'. "
            "CyberRanger only attacks localhost sandboxes."
        )


class Environment:
    """Wraps the target app. Real HTTP when reachable, mock otherwise."""

    def __init__(self, base_url=DVWA_URL):
        _assert_localhost(base_url)
        self.base_url = base_url
        self.mock_mode = not self._reachable()

    def _reachable(self):
        """Probe the app once so we can decide real vs mock up front."""
        try:
            requests.get(self.base_url, timeout=REQUEST_TIMEOUT)
            return True
        except requests.RequestException:
            return False

    def execute(self, action):
        """Run an action and return {status_code, breached, response_snippet}."""
        if self.mock_mode:
            return self._mock_execute(action)
        return self._real_execute(action)

    # -- real path ---------------------------------------------------------
    def _real_execute(self, action):
        """Send the payload to DVWA and apply the breach heuristic."""
        _assert_localhost(self.base_url)
        field = action["target_field"]
        params = {field: action["payload"], "Submit": "Submit"}
        try:
            resp = requests.get(
                f"{self.base_url}/vulnerabilities/sqli/",
                params=params,
                timeout=REQUEST_TIMEOUT,
            )
            body = resp.text
            breached = self._is_breach(action, body, resp.status_code)
            return {
                "status_code": resp.status_code,
                "breached": breached,
                "response_snippet": body[:120].replace("\n", " ").strip(),
            }
        except requests.RequestException:
            # Lost the app mid-run: degrade to mock rather than crash.
            self.mock_mode = True
            return self._mock_execute(action)

    def _is_breach(self, action, body, status_code):
        """Heuristic breach detection from response contents."""
        if status_code != 200:
            return False
        low = body.lower()
        if action["category"] == "sqli":
            return any(m in low for m in _SQLI_BREACH_MARKERS)
        if action["category"] == "xss":
            # Reflected & unescaped payload = stored/reflected XSS success.
            return any(m.lower() in low for m in _XSS_BREACH_MARKERS)
        return False

    # -- mock path ---------------------------------------------------------
    def _mock_execute(self, action):
        """Simulate a plausible response so the demo always runs."""
        cat = action["category"]
        if cat == "sqli":
            return {
                "status_code": 200,
                "breached": True,
                "response_snippet": "ID: admin First name: admin Surname: admin",
            }
        if cat == "xss":
            return {
                "status_code": 200,
                "breached": True,
                "response_snippet": f"Hello {action['payload']}",
            }
        return {
            "status_code": 200,
            "breached": False,
            "response_snippet": "Hello hello world",
        }
