import hashlib
import re
import sys
import time
from typing import Any, Optional
import requests

from cyberranger.genome import Genome, TrialResult, VulnClass
from cyberranger.scoring import score_detection, score_target_compromise


class SandboxClient:
    """Client that dispatches payloads to dvwa-target and mirrors traffic to blue-detector (§6)."""

    def __init__(
        self,
        target_base_url: str = "http://127.0.0.1:8080",
        detector_base_url: str = "http://127.0.0.1:8000",
        username: str = "admin",
        password: str = "password",
        security_level: str = "low",
        log_to_stdout: bool = True,
    ):
        self.target_base_url = target_base_url.rstrip("/")
        self.detector_base_url = detector_base_url.rstrip("/")
        self.username = username
        self.password = password
        self.security_level = security_level
        self.log_to_stdout = log_to_stdout
        self.session = requests.Session()
        self.authenticated = False

    def _log(self, message: str):
        if self.log_to_stdout:
            print(f"[SandboxClient] {message}", file=sys.stdout, flush=True)

    def extract_csrf_token(self, html: str) -> Optional[str]:
        """Extract CSRF user_token from DVWA response forms."""
        match = re.search(r"name='user_token'\s+value='([^']+)'", html)
        if match:
            return match.group(1)
        match_alt = re.search(r'name="user_token"\s+value="([^"]+)"', html)
        if match_alt:
            return match_alt.group(1)
        return None

    def ensure_dvwa_ready(self):
        """Ensure DVWA database is initialized and session is authenticated with security level set."""
        if self.authenticated:
            return

        try:
            # 1. Check or initialize Database setup
            setup_url = f"{self.target_base_url}/setup.php"
            setup_page = self.session.get(setup_url, timeout=10)
            if "Create / Reset Database" in setup_page.text:
                token = self.extract_csrf_token(setup_page.text)
                post_data = {"create_db": "Create / Reset Database"}
                if token:
                    post_data["user_token"] = token
                self.session.post(setup_url, data=post_data, timeout=10)
                self._log("DVWA database initialized.")

            # 2. Login
            login_url = f"{self.target_base_url}/login.php"
            login_page = self.session.get(login_url, timeout=10)
            token = self.extract_csrf_token(login_page.text)
            login_data = {
                "username": self.username,
                "password": self.password,
                "Login": "Login",
            }
            if token:
                login_data["user_token"] = token

            login_resp = self.session.post(login_url, data=login_data, timeout=10)
            if "login.php" in login_resp.url and "Login" in login_resp.text and "logout.php" not in login_resp.text:
                self._log("Warning: DVWA login may not have succeeded.")
            else:
                self._log(f"Authenticated as '{self.username}' on DVWA.")

            # 3. Set security level
            sec_url = f"{self.target_base_url}/security.php"
            sec_page = self.session.get(sec_url, timeout=10)
            sec_token = self.extract_csrf_token(sec_page.text)
            sec_data = {
                "security": self.security_level,
                "seclev_submit": "Submit",
            }
            if sec_token:
                sec_data["user_token"] = sec_token
            self.session.post(sec_url, data=sec_data, timeout=10)
            self._log(f"DVWA security level configured to '{self.security_level}'.")

            self.authenticated = True
        except Exception as e:
            self._log(f"Initialization error (continuing anyway): {e}")

    def fire(self, genome: Genome) -> TrialResult:
        """Fire a genome's rendered payload against dvwa-target and score with blue-detector (§6)."""
        self.ensure_dvwa_ready()

        payload = genome.rendered_payload
        start_time = time.perf_counter()

        target_resp_text = ""
        target_status_code = 0
        req_url = ""
        req_params: dict[str, Any] = {}
        req_body: Optional[str] = None
        req_method = "GET"

        try:
            # Map vulnerability class to DVWA endpoints
            if genome.vuln_class == VulnClass.SQLI:
                req_url = f"{self.target_base_url}/vulnerabilities/sqli/"
                req_params = {"id": payload, "Submit": "Submit"}
                resp = self.session.get(req_url, params=req_params, timeout=10)

            elif genome.vuln_class == VulnClass.XSS:
                req_url = f"{self.target_base_url}/vulnerabilities/xss_r/"
                req_params = {"name": payload}
                resp = self.session.get(req_url, params=req_params, timeout=10)

            elif genome.vuln_class == VulnClass.COMMAND_INJECTION:
                req_url = f"{self.target_base_url}/vulnerabilities/exec/"
                req_method = "POST"
                req_data = {"ip": payload, "Submit": "Submit"}
                req_body = str(req_data)
                resp = self.session.post(req_url, data=req_data, timeout=10)

            elif genome.vuln_class == VulnClass.PATH_TRAVERSAL:
                req_url = f"{self.target_base_url}/vulnerabilities/fi/"
                req_params = {"page": payload}
                resp = self.session.get(req_url, params=req_params, timeout=10)

            else:
                # Default / SSRF endpoint
                req_url = f"{self.target_base_url}/vulnerabilities/sqli/"
                req_params = {"id": payload, "Submit": "Submit"}
                resp = self.session.get(req_url, params=req_params, timeout=10)

            target_resp_text = resp.text
            target_status_code = resp.status_code
        except Exception as e:
            target_resp_text = f"ConnectionError: {str(e)}"
            target_status_code = 500

        latency_ms = int((time.perf_counter() - start_time) * 1000)

        # Compromise scoring
        compromised, compromise_conf = score_target_compromise(
            target_resp_text, target_status_code, payload=payload
        )

        # Mirror traffic to blue-detector
        detector_flagged = False
        detector_confidence = 0.0
        detector_rule_fired = None

        try:
            detector_payload = {
                "url": req_url,
                "method": req_method,
                "params": req_params,
                "body": req_body,
            }
            det_resp = requests.post(
                f"{self.detector_base_url}/detect",
                json=detector_payload,
                timeout=5,
            )
            if det_resp.status_code == 200:
                detector_flagged, detector_confidence, detector_rule_fired = score_detection(
                    det_resp.json()
                )
        except Exception as e:
            self._log(f"Warning: blue-detector mirror call failed: {e}")

        # Compute fingerprint and excerpt
        response_signature = hashlib.sha256(target_resp_text.encode("utf-8", errors="ignore")).hexdigest()
        raw_response_excerpt = target_resp_text[:300].replace("\n", " ").strip()

        result = TrialResult(
            genome_id=genome.id,
            target_compromised=compromised,
            compromise_confidence=compromise_conf,
            detector_flagged=detector_flagged,
            detector_confidence=detector_confidence,
            detector_rule_fired=detector_rule_fired,
            response_signature=response_signature,
            latency_ms=latency_ms,
            raw_response_excerpt=raw_response_excerpt,
        )

        payload_str = f"'{payload[:60]}...'" if len(payload) > 60 else f"'{payload}'"
        self._log(
            f"Fired Genome {genome.id[:8]} [{genome.vuln_class.value}] ({genome.operator_used}): "
            f"Compromised={result.target_compromised} (conf={result.compromise_confidence:.2f}), "
            f"DetectorFlagged={result.detector_flagged} (conf={result.detector_confidence:.2f}), "
            f"Latency={result.latency_ms}ms, "
            f"Payload={payload_str}"
        )

        return result
