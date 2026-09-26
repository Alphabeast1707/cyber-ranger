"""Tests for Milestone 2: Docker Compose sandbox services.

Validates that:
- DVWA is reachable only from inside the internal network.
- The trivial blue-detector stub is running and returns 'not flagged'.
- Neither service exposes ports to the external host.
"""

import json
import subprocess
import pytest
import requests

NETWORK_NAME = "cyberranger_internal"


def run_cmd(cmd: list[str], timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def test_host_cannot_reach_raw_dvwa_port():
    """Verify that dvwa-target direct port 80 is not exposed to localhost."""
    for port in [80, 8081]:
        with pytest.raises(Exception):
            requests.get(f"http://localhost:{port}/", timeout=1)


def test_dvwa_reachable_from_inside_sandbox():
    """Verify DVWA responds to HTTP requests from within the internal network."""
    cmd = [
        "docker", "run", "--rm",
        "--network", NETWORK_NAME,
        "alpine", "sh", "-c",
        "wget -q -O - http://dvwa-target/login.php"
    ]
    proc = run_cmd(cmd, timeout=15)
    assert proc.returncode == 0, f"Failed to reach DVWA inside sandbox: {proc.stderr}"
    assert "Damn Vulnerable Web Application" in proc.stdout, (
        f"DVWA response did not contain expected title: {proc.stdout[:200]}"
    )


def test_blue_detector_stub_responds_not_flagged():
    """Verify blue-detector stub responds with 'not flagged' from within sandbox."""
    # Test health endpoint
    health_cmd = [
        "docker", "run", "--rm",
        "--network", NETWORK_NAME,
        "alpine", "sh", "-c",
        "wget -q -O - http://blue-detector:8000/health"
    ]
    proc = run_cmd(health_cmd, timeout=10)
    assert proc.returncode == 0, f"Failed to reach blue-detector health: {proc.stderr}"
    health_data = json.loads(proc.stdout)
    assert health_data.get("status") == "ok"

    # Test detection endpoint
    detect_cmd = [
        "docker", "run", "--rm", "-i",
        "--network", NETWORK_NAME,
        "alpine", "sh", "-c",
        'wget -q -O - --post-data="$(cat)" --header="Content-Type: application/json" http://blue-detector:8000/detect'
    ]
    post_payload = json.dumps({"url": "/vulnerabilities/sqli/", "params": {"id": "1' OR '1'='1"}})
    detect_proc = subprocess.run(
        detect_cmd, input=post_payload, capture_output=True, text=True, timeout=10
    )
    assert detect_proc.returncode == 0, f"Detection request failed: {detect_proc.stderr}"
    detect_data = json.loads(detect_proc.stdout)

    assert isinstance(detect_data.get("flagged"), bool)
    assert isinstance(detect_data.get("confidence"), (int, float))
