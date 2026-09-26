"""Tests for extended Triage UI and REST API endpoints (§9, §11, §13)."""

from fastapi.testclient import TestClient
import pytest

from cyberranger.genome import BehaviorDescriptor, EvasionTechnique, Genome, TrialResult, VulnClass
from triage_ui.app import app, triage_queue, get_orchestrator


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def populated_queue():
    g1 = Genome(vuln_class=VulnClass.SQLI, rendered_payload="1' OR '1'='1")
    tr1 = TrialResult(
        genome_id=g1.id,
        target_compromised=True,
        compromise_confidence=0.98,
        detector_flagged=False,
        detector_confidence=0.1,
        detector_rule_fired=None,
        response_signature="sig_sql_1",
        latency_ms=10,
        raw_response_excerpt="admin dump",
    )
    bd1 = BehaviorDescriptor(
        vuln_class=VulnClass.SQLI,
        injection_point_category="auth_form",
        evasion_technique=EvasionTechnique.NONE,
        detector_outcome="undetected",
    )
    item1 = triage_queue.enqueue(g1, tr1, bd1, "new_cell", 0.95)

    g2 = Genome(vuln_class=VulnClass.XSS, rendered_payload="<script>alert(1)</script>")
    tr2 = TrialResult(
        genome_id=g2.id,
        target_compromised=True,
        compromise_confidence=0.9,
        detector_flagged=True,
        detector_confidence=0.9,
        detector_rule_fired="rule_xss",
        response_signature="sig_xss_1",
        latency_ms=8,
        raw_response_excerpt="alert",
    )
    bd2 = BehaviorDescriptor(
        vuln_class=VulnClass.XSS,
        injection_point_category="search",
        evasion_technique=EvasionTechnique.COMMENT_INJECTION,
        detector_outcome="flagged_high_confidence",
    )
    item2 = triage_queue.enqueue(g2, tr2, bd2, "new_cell", 0.6)

    return item1, item2


def test_api_status_endpoint(client):
    """Verify /api/status returns live status dictionary."""
    resp = client.get("/api/status")
    assert resp.status_code == 200
    data = resp.json()
    assert "sandbox_network" in data
    assert "dvwa_target" in data
    assert "blue_detector" in data
    assert "coevolution" in data
    assert "triage" in data


def test_api_archive_matrix_endpoint(client):
    """Verify /api/archive/matrix returns cell structure."""
    resp = client.get("/api/archive/matrix")
    assert resp.status_code == 200
    data = resp.json()
    assert "cells" in data
    assert "filled_count" in data
    assert "qd_score" in data


def test_api_metrics_endpoint(client):
    """Verify /api/metrics returns historical log array."""
    resp = client.get("/api/metrics")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_api_hall_of_fame_endpoint(client):
    """Verify /api/hall-of-fame returns entries."""
    resp = client.get("/api/hall-of-fame")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_batch_review_action(client, populated_queue):
    """Verify /api/triage/batch confirms multiple items."""
    item1, item2 = populated_queue
    resp = client.post(
        "/api/triage/batch",
        json={
            "ids": [item1.id, item2.id],
            "action": "confirm",
            "reviewer_note": "Batch approved by analyst",
            "reviewer_id": "test_lead",
        },
    )
    assert resp.status_code == 200
    res_data = resp.json()
    assert res_data["updated_count"] == 2

    # Verify they were updated
    for it_id in [item1.id, item2.id]:
        check_resp = client.get(f"/api/triage/{it_id}")
        assert check_resp.json()["status"] == "confirmed"


def test_orchestrator_step_endpoint(client):
    """Verify /api/orchestrator/step fires a generation step."""
    resp = client.post("/api/orchestrator/step")
    assert resp.status_code == 200
    data = resp.json()
    assert "generation" in data
    assert "arm_used" in data
    assert "events" in data
