"""Tests for Milestone 8 (§14):
- Blue learner retraining loop (§10)
- Model artifact persistence
- Blue-detector service hot-reload and real detection
"""

import time
import pytest
import requests

from cyberranger.blue_learner import BlueLearner, build_feature_matrix
from cyberranger.genome import BehaviorDescriptor, EvasionTechnique, Genome, TrialResult, VulnClass
from cyberranger.triage import TriageItem


@pytest.fixture
def sample_confirmed_items():
    """Create a batch of confirmed triage items with diverse attack classes."""
    items = []
    attacks = [
        (VulnClass.SQLI, "1' OR '1'='1", "id"),
        (VulnClass.SQLI, "' UNION SELECT user, password FROM users --", "query"),
        (VulnClass.COMMAND_INJECTION, "127.0.0.1; cat /etc/passwd", "ip"),
        (VulnClass.COMMAND_INJECTION, "localhost && whoami", "cmd"),
        (VulnClass.XSS, "<script>alert('pwned')</script>", "name"),
        (VulnClass.PATH_TRAVERSAL, "../../../../etc/passwd", "file"),
    ]
    for i, (vuln, payload, ip) in enumerate(attacks):
        g = Genome(
            vuln_class=vuln,
            injection_point=ip,
            rendered_payload=payload,
            evasion_technique=EvasionTechnique.NONE,
        )
        tr = TrialResult(
            genome_id=g.id,
            target_compromised=True,
            compromise_confidence=0.95,
            detector_flagged=False,
            detector_confidence=0.0,
            detector_rule_fired=None,
            response_signature=f"sig_{i}",
            latency_ms=20,
            raw_response_excerpt="output",
        )
        bd = BehaviorDescriptor(
            vuln_class=vuln,
            injection_point_category="search",
            evasion_technique=EvasionTechnique.NONE,
            detector_outcome="undetected",
        )
        item = TriageItem(
            id=f"confirmed_{i}",
            genome=g,
            trial_result=tr,
            behavior_descriptor=bd,
            archive_cell_status="new_cell",
            fitness=0.95,
            status="confirmed",
        )
        items.append(item)
    return items


def test_build_feature_matrix(sample_confirmed_items):
    """Verify feature matrix contains generalization markers rather than raw strings."""
    X, y = build_feature_matrix(sample_confirmed_items)
    assert len(X) == len(y)
    assert len(X) > len(sample_confirmed_items)  # Includes negative samples
    assert 1 in y and 0 in y  # Both classes present
    assert all(isinstance(row, list) for row in X)
    assert all(isinstance(v, (int, float)) for row in X for v in row)


def test_blue_learner_retrain_and_hot_reload(sample_confirmed_items):
    """Verify blue learner retrains random forest and hot-reloads running detector service."""
    learner = BlueLearner(detector_api_url="http://127.0.0.1:8000")

    # Retrain
    model, model_path = learner.retrain(sample_confirmed_items)
    assert model_path.exists()
    assert (learner.models_dir / "latest_model.joblib").exists()

    # Give hot-reload a moment to propagate in container
    time.sleep(1)

    # Check detector service health
    health_resp = requests.get("http://127.0.0.1:8000/health", timeout=5)
    assert health_resp.status_code == 200
    health_data = health_resp.json()
    assert health_data.get("has_model") is True

    # Test detection on an attack payload (should now be flagged with high confidence!)
    attack_req = {
        "url": "/vulnerabilities/sqli/",
        "params": {"id": "1' OR '1'='1 --"},
    }
    det_resp = requests.post("http://127.0.0.1:8000/detect", json=attack_req, timeout=5)
    assert det_resp.status_code == 200
    det_data = det_resp.json()
    assert det_data.get("flagged") is True, f"Trained model failed to flag attack: {det_data}"
    assert det_data.get("confidence") >= 0.5
    assert det_data.get("rule_fired") is not None

    # Test detection on normal benign request (should NOT be flagged)
    benign_req = {
        "url": "/index.php",
        "params": {"page": "home"},
    }
    benign_resp = requests.post("http://127.0.0.1:8000/detect", json=benign_req, timeout=5)
    assert benign_resp.status_code == 200
    benign_data = benign_resp.json()
    assert benign_data.get("flagged") is False, f"Benign traffic was falsely flagged: {benign_data}"
