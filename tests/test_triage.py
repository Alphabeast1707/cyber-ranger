"""Tests for Milestone 7 (§14):
- Human triage queue (§3, §9)
- Triage FastAPI endpoints and status transitions
"""

from fastapi.testclient import TestClient
import pytest

from cyberranger.genome import BehaviorDescriptor, EvasionTechnique, Genome, TrialResult, VulnClass
from cyberranger.triage import TriageQueue
from triage_ui.app import app, triage_queue as global_queue


@pytest.fixture
def sample_triage_data():
    g = Genome(vuln_class=VulnClass.SQLI, payload_template="' OR 1=1--", rendered_payload="' OR 1=1--")
    tr = TrialResult(
        genome_id=g.id,
        target_compromised=True,
        compromise_confidence=0.9,
        detector_flagged=False,
        detector_confidence=0.0,
        detector_rule_fired=None,
        response_signature="sig1",
        latency_ms=25,
        raw_response_excerpt="root admin",
    )
    bd = BehaviorDescriptor(
        vuln_class=VulnClass.SQLI,
        injection_point_category="auth_form",
        evasion_technique=EvasionTechnique.NONE,
        detector_outcome="undetected",
    )
    return g, tr, bd


def test_triage_queue_lifecycle(sample_triage_data):
    """Verify queue enqueue, retrieval, status updates, and batch pulling."""
    g, tr, bd = sample_triage_data
    queue = TriageQueue()

    item = queue.enqueue(g, tr, bd, archive_cell_status="new_cell", fitness=0.9)
    assert item.status == "pending"
    assert len(queue.list_items("pending")) == 1

    # Pull before confirm -> empty
    assert len(queue.pull_confirmed_since_last_pass()) == 0

    # Confirm item
    updated = queue.update_status(item.id, "confirmed", reviewer_note="Verified real exploit")
    assert updated.status == "confirmed"
    assert updated.reviewer_note == "Verified real exploit"
    assert updated.reviewed_at is not None

    # Pull after confirm -> returns item exactly once
    confirmed_batch = queue.pull_confirmed_since_last_pass()
    assert len(confirmed_batch) == 1
    assert confirmed_batch[0].id == item.id

    # Second pull -> already consumed
    assert len(queue.pull_confirmed_since_last_pass()) == 0


def test_triage_api_endpoints(sample_triage_data):
    """Verify FastAPI triage portal endpoints and HTML dashboard."""
    g, tr, bd = sample_triage_data
    item = global_queue.enqueue(g, tr, bd, archive_cell_status="new_cell", fitness=0.95)

    client = TestClient(app)

    # 1. HTML Dashboard
    resp = client.get("/")
    assert resp.status_code == 200
    assert "CyberRanger" in resp.text
    assert item.id[:8] in resp.text

    # 2. JSON list
    list_resp = client.get("/api/triage")
    assert list_resp.status_code == 200
    items = list_resp.json()
    assert any(i["id"] == item.id for i in items)

    # 3. Confirm item via API
    confirm_resp = client.post(
        f"/api/triage/{item.id}",
        json={"action": "confirm", "reviewer_note": "Approved by API test"},
    )
    assert confirm_resp.status_code == 200
    assert confirm_resp.json()["status"] == "confirmed"

    # 4. Check status was updated
    get_resp = client.get(f"/api/triage/{item.id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["status"] == "confirmed"
