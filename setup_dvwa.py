"""One-command DVWA initializer for CyberRanger Arena.

DVWA needs a one-time 'Create / Reset Database' step before its vulnerabilities
work. Doing it by hand in the browser is easy to forget before a demo, so this
script performs it over HTTP: log in, create the database, set security to low,
then fire one real payload per category to confirm live breaches.

    uv run python setup_dvwa.py

Safe + local-only: it talks to http://localhost:8080 exclusively.
"""

import re
import sys
import requests

BASE = "http://localhost:8080"
USER, PASS = "admin", "password"


def _token(html):
    m = re.search(r"name=['\"]user_token['\"]\s+value=['\"]([^'\"]+)", html)
    return m.group(1) if m else None


def _login(s):
    r = s.get(f"{BASE}/login.php", timeout=5)
    s.post(f"{BASE}/login.php",
           data={"username": USER, "password": PASS, "Login": "Login",
                 "user_token": _token(r.text)},
           timeout=5, allow_redirects=True)


def main():
    if "localhost" not in BASE and "127.0.0.1" not in BASE:
        sys.exit("Refusing non-local target.")
    s = requests.Session()
    try:
        _login(s)
        # Create / reset the database (idempotent).
        r = s.get(f"{BASE}/setup.php", timeout=5)
        s.post(f"{BASE}/setup.php",
               data={"create_db": "Create / Reset Database",
                     "user_token": _token(r.text)},
               timeout=25)
        _login(s)                     # DB reset logs us out — log back in
        s.cookies.set("security", "low")
        print("[+] Database created, security level set to low.")
    except requests.RequestException as e:
        sys.exit(f"[!] DVWA not reachable at {BASE} — is the container up? ({e})")

    # Confirm real breaches across all four vulnerability classes.
    checks = {
        "sqli": ("GET", "/vulnerabilities/sqli/", "id", "1' OR '1'='1",
                 ["first name", "surname"]),
        "xss": ("GET", "/vulnerabilities/xss_r/", "name",
                "<script>alert(1)</script>", ["<script>alert(1)"]),
        "cmdi": ("POST", "/vulnerabilities/exec/", "ip", "-c 1 127.0.0.1; id",
                 ["uid="]),
        "traversal": ("GET", "/vulnerabilities/fi/", "page", "/etc/passwd",
                      ["root:"]),
    }
    all_ok = True
    for cat, (method, path, field, payload, markers) in checks.items():
        try:
            if method == "POST":
                r = s.post(f"{BASE}{path}", data={field: payload, "Submit": "Submit"}, timeout=5)
            else:
                r = s.get(f"{BASE}{path}", params={field: payload, "Submit": "Submit"}, timeout=5)
            ok = any(m in r.text.lower() for m in markers)
        except requests.RequestException:
            ok = False
        all_ok &= ok
        print(f"    {cat:10} {'live breach OK' if ok else 'FAILED'}")

    print("\n[+] DVWA is ready — run the demo with:  uv run python server.py"
          if all_ok else
          "\n[!] Some checks failed — the demo will still run in SANDBOX (mock) mode.")


if __name__ == "__main__":
    main()
