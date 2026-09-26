"""Tests for sandbox network isolation (§0 and §14 Milestone 1).

The safety boundary dictates:
- All attack traffic stays inside a Docker user-defined bridge network with `internal: true`.
- No container inside this network can reach any external host or IP.
- No container inside this network can resolve external DNS names.
- Internal communication between sandbox services is permitted.
- The target hostname is hardcoded to 'dvwa-target' and never accepted as an arbitrary runtime target.
"""

import json
from pathlib import Path
import subprocess
import time
import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
COMPOSE_FILE = REPO_ROOT / "docker-compose.yml"
CONFIG_FILE = REPO_ROOT / "config" / "default.yaml"
NETWORK_NAME = "cyberranger_internal"


def run_cmd(cmd: list[str], timeout: int = 30) -> subprocess.CompletedProcess:
    """Run a shell command and return CompletedProcess."""
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


@pytest.fixture(scope="module")
def ensure_internal_network():
    """Ensure that the internal sandbox network is created in Docker."""
    # Check if network exists
    proc = run_cmd(["docker", "network", "inspect", NETWORK_NAME])
    if proc.returncode != 0:
        # Create it explicitly if not present
        create_proc = run_cmd([
            "docker", "network", "create",
            "--internal",
            NETWORK_NAME
        ])
        assert create_proc.returncode == 0, f"Failed to create network: {create_proc.stderr}"

    yield NETWORK_NAME


def test_compose_file_specifies_internal_network():
    """Verify docker-compose.yml defines cyberranger_internal with internal: true."""
    assert COMPOSE_FILE.exists(), f"Missing docker-compose.yml at {COMPOSE_FILE}"
    with open(COMPOSE_FILE, "r") as f:
        compose_data = yaml.safe_load(f)

    assert "networks" in compose_data, "No networks defined in docker-compose.yml"
    assert "cyberranger_internal" in compose_data["networks"], "cyberranger_internal network not found"

    net_cfg = compose_data["networks"]["cyberranger_internal"]
    assert net_cfg.get("internal") is True, (
        "cyberranger_internal must have 'internal: true' to ensure no internet egress"
    )

    # Verify services attach to internal network and have no host ports exposed
    services = compose_data.get("services", {})
    assert "dvwa-target" in services, "dvwa-target service missing from docker-compose.yml"
    assert "blue-detector" in services, "blue-detector service missing from docker-compose.yml"

    for svc_name in ["dvwa-target", "blue-detector"]:
        svc_cfg = services.get(svc_name, {})
        assert "ports" not in svc_cfg, (
            f"Service {svc_name} has ports exposed to host. Attack surface must remain internal-only."
        )
        svc_networks = svc_cfg.get("networks", [])
        if isinstance(svc_networks, dict):
            svc_networks = list(svc_networks.keys())
        assert "cyberranger_internal" in svc_networks, (
            f"Service {svc_name} is not connected to cyberranger_internal network"
        )


def test_config_file_specifies_internal_sandbox():
    """Verify config/default.yaml configures the sandbox services properly."""
    assert CONFIG_FILE.exists(), f"Missing config file at {CONFIG_FILE}"
    with open(CONFIG_FILE, "r") as f:
        config_data = yaml.safe_load(f)

    sandbox_cfg = config_data.get("sandbox", {})
    assert sandbox_cfg.get("network_name") == NETWORK_NAME
    assert sandbox_cfg.get("target_service") == "dvwa-target"
    assert sandbox_cfg.get("detector_service") == "blue-detector"


def test_sandbox_network_is_internal_in_docker(ensure_internal_network):
    """Verify docker network inspect shows Internal == true."""
    proc = run_cmd(["docker", "network", "inspect", NETWORK_NAME])
    assert proc.returncode == 0, f"docker network inspect failed: {proc.stderr}"

    inspect_data = json.loads(proc.stdout)
    assert len(inspect_data) > 0
    net_info = inspect_data[0]
    assert net_info.get("Internal") is True, (
        f"Network {NETWORK_NAME} does not have Internal=True in Docker daemon"
    )


def test_sandbox_blocks_external_ip_traffic(ensure_internal_network):
    """Assert that a container attached to cyberranger_internal cannot reach external IPs."""
    # Ping test to external IP (8.8.8.8)
    ping_cmd = [
        "docker", "run", "--rm",
        "--network", NETWORK_NAME,
        "alpine", "sh", "-c", "ping -c 1 -W 2 8.8.8.8"
    ]
    proc = run_cmd(ping_cmd, timeout=10)
    assert proc.returncode != 0, (
        f"Security violation! External ping succeeded from inside sandbox network: {proc.stdout}"
    )

    # TCP connect test to external IP (1.1.1.1:80)
    nc_cmd = [
        "docker", "run", "--rm",
        "--network", NETWORK_NAME,
        "alpine", "sh", "-c", "nc -z -w 2 1.1.1.1 80"
    ]
    proc = run_cmd(nc_cmd, timeout=10)
    assert proc.returncode != 0, (
        f"Security violation! External TCP connect succeeded from inside sandbox network: {proc.stdout}"
    )


def test_sandbox_blocks_external_dns_resolution(ensure_internal_network):
    """Assert that a container attached to cyberranger_internal cannot resolve external domains."""
    for domain in ["google.com", "example.com", "cloudflare.com"]:
        cmd = [
            "docker", "run", "--rm",
            "--network", NETWORK_NAME,
            "alpine", "sh", "-c", f"nslookup {domain}"
        ]
        proc = run_cmd(cmd, timeout=10)
        assert proc.returncode != 0, (
            f"Security violation! External DNS resolution for {domain} succeeded: {proc.stdout}"
        )


def test_sandbox_allows_internal_communication(ensure_internal_network):
    """Assert that containers within the internal network CAN communicate with each other."""
    server_container = "test_internal_server"
    client_container = "test_internal_client"

    # Cleanup any leftovers
    run_cmd(["docker", "rm", "-f", server_container, client_container])

    try:
        # Start a simple internal echo/nc server container
        start_server = run_cmd([
            "docker", "run", "-d",
            "--name", server_container,
            "--network", NETWORK_NAME,
            "alpine", "nc", "-l", "-p", "9999"
        ])
        assert start_server.returncode == 0, f"Failed to start test server: {start_server.stderr}"

        # Give server a moment to bind
        time.sleep(0.5)

        # Connect from a client container using server container name
        client_test = run_cmd([
            "docker", "run", "--rm",
            "--name", client_container,
            "--network", NETWORK_NAME,
            "alpine", "sh", "-c", f"nc -z -w 3 {server_container} 9999"
        ], timeout=10)

        assert client_test.returncode == 0, (
            f"Internal network communication failed between sandbox containers: {client_test.stderr}"
        )
    finally:
        run_cmd(["docker", "rm", "-f", server_container])
