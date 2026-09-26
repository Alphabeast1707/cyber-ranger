"""Tests for Milestone 9 (§14):
- Hall of Fame archiving (§3, §11)
- Blue regression pass testing active detector against red elites
- Red regression pass testing population against retired blue models
"""

import pytest

from cyberranger.blue_learner import BlueLearner
from cyberranger.genome import BehaviorDescriptor, EvasionTechnique, Genome, TrialResult, VulnClass
from cyberranger.hall_of_fame import HallOfFame
from cyberranger.triage import TriageItem


@pytest.fixture
def trained_blue_and_elites(tmp_path):
    """Set up a trained blue model and a set of red elites."""
    hof = HallOfFame()

    # Create 3 confirmed red items
    items = []
    for i, payload in enumerate(["1' OR '1'='1", "admin' --", "' UNION SELECT 1, 2 #"]):
        g = Genome(
            vuln_class=VulnClass.SQLI,
            injection_point="id",
            rendered_payload=payload,
            evasion_technique=EvasionTechnique.NONE,
        )
        tr = TrialResult(
            genome_id=g.id,
            target_compromised=True,
            compromise_confidence=0.9,
            detector_flagged=False,
            detector_confidence=0.0,
            detector_rule_fired=None,
            response_signature=f"s_{i}",
            latency_ms=15,
            raw_response_excerpt="out",
        )
        bd = BehaviorDescriptor(
            vuln_class=VulnClass.SQLI,
            injection_point_category="search",
            evasion_technique=EvasionTechnique.NONE,
            detector_outcome="undetected",
        )
        item = TriageItem(
            id=f"t_{i}",
            genome=g,
            trial_result=tr,
            behavior_descriptor=bd,
            archive_cell_status="new_cell",
            fitness=0.9,
            status="confirmed",
        )
        items.append(item)
        hof.archive_red_elite(g, generation=1)

    # Train a blue model on these items
    learner = BlueLearner(models_dir=tmp_path / "models")
    model, model_path = learner.retrain(items)
    hof.archive_blue_snapshot(str(model_path), generation=1)

    return hof, model, model_path


def test_hall_of_fame_archiving(trained_blue_and_elites):
    """Verify red elites and blue snapshots are archived properly."""
    hof, model, model_path = trained_blue_and_elites

    assert len(hof.get_red_elites()) == 3
    assert len(hof.get_blue_snapshots()) == 1
    assert hof.get_blue_snapshots()[0] == str(model_path)


def test_blue_regression_pass_detection_rate(trained_blue_and_elites):
    """Verify active blue model flags historical red elites (regression test)."""
    hof, model, _ = trained_blue_and_elites

    # Test the trained model against all red elites
    pass_rate = hof.test_blue_against_all_red_elites(model)
    assert pass_rate >= 0.9, f"Trained blue model had low pass rate: {pass_rate}"

    # Test a dummy stub that flags nothing -> regression detected!
    class DummyStub:
        def predict(self, req):
            return False, 0.0, None

    stub_pass_rate = hof.test_blue_against_all_red_elites(DummyStub())
    assert stub_pass_rate == 0.0, "Dummy stub should fail all historical red elites"


def test_red_regression_pass_evasion_rate(trained_blue_and_elites):
    """Verify red population genomes are evaluated against retired blue models."""
    hof, _, model_path = trained_blue_and_elites

    # Genomes with subtle evasions
    evasive_genomes = [
        Genome(
            vuln_class=VulnClass.SQLI,
            injection_point="search",
            rendered_payload="regular_text_with_no_sql",
        ),
    ]

    evasion_rate = hof.test_population_against_retired_blue(evasive_genomes, retired_model_path=str(model_path))
    assert evasion_rate == 1.0  # Successfully evaded detector
