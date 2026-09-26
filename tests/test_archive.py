"""Tests for Milestone 4 (§14):
- Archive and BehaviorDescriptor (§3, §8)
- Confirms cells fill sensibly on real traffic against DVWA
"""

import pytest

from cyberranger.archive import Archive
from cyberranger.behavior import compute_behavior_descriptor
from cyberranger.genome import BehaviorDescriptor, EvasionTechnique, Genome, TrialResult, VulnClass
from cyberranger.operators.grammar import GrammarOperator
from cyberranger.sandbox_client import SandboxClient
from cyberranger.scoring import combined_fitness


def test_archive_insertion_logic():
    """Verify Archive insertion rules: new_cell, replaced_incumbent, rejected."""
    archive = Archive()
    g1 = Genome(vuln_class=VulnClass.SQLI, injection_point="search.query")
    tr1 = TrialResult(
        genome_id=g1.id,
        target_compromised=True,
        compromise_confidence=0.8,
        detector_flagged=False,
        detector_confidence=0.0,
        detector_rule_fired=None,
        response_signature="sig1",
        latency_ms=20,
        raw_response_excerpt="result",
    )
    bd1 = BehaviorDescriptor(
        vuln_class=VulnClass.SQLI,
        injection_point_category="search",
        evasion_technique=EvasionTechnique.NONE,
        detector_outcome="undetected",
    )

    # First insert -> new_cell
    res1 = archive.try_insert(g1, tr1, bd1, fitness=0.8)
    assert res1 == "new_cell"
    assert len(archive.cells) == 1
    assert archive.qd_score() == 0.8
    assert archive.coverage(total_possible_cells=10) == 0.1

    # Insert with lower fitness -> rejected
    g2 = Genome(vuln_class=VulnClass.SQLI, injection_point="search.query")
    tr2 = TrialResult(
        genome_id=g2.id,
        target_compromised=True,
        compromise_confidence=0.5,
        detector_flagged=False,
        detector_confidence=0.0,
        detector_rule_fired=None,
        response_signature="sig2",
        latency_ms=18,
        raw_response_excerpt="result",
    )
    res2 = archive.try_insert(g2, tr2, bd1, fitness=0.5)
    assert res2 == "rejected"
    assert archive.qd_score() == 0.8

    # Insert with higher fitness -> replaced_incumbent
    g3 = Genome(vuln_class=VulnClass.SQLI, injection_point="search.query")
    tr3 = TrialResult(
        genome_id=g3.id,
        target_compromised=True,
        compromise_confidence=0.95,
        detector_flagged=False,
        detector_confidence=0.0,
        detector_rule_fired=None,
        response_signature="sig3",
        latency_ms=22,
        raw_response_excerpt="result",
    )
    res3 = archive.try_insert(g3, tr3, bd1, fitness=0.95)
    assert res3 == "replaced_incumbent"
    assert archive.qd_score() == 0.95

    # Summary for LLM
    summary = archive.summary_for_llm()
    assert summary["total_filled_cells"] == 1
    assert summary["qd_score"] == 0.95
    assert len(summary["explored_cells"]) == 1


def test_archive_fills_sensibly_on_real_traffic():
    """Fire a batch of diverse grammar payloads at sandbox and confirm archive cells fill sensibly."""
    archive = Archive()
    client = SandboxClient(
        target_base_url="http://127.0.0.1:8080",
        detector_base_url="http://127.0.0.1:8000",
        log_to_stdout=False,
    )
    grammar_op = GrammarOperator()

    classes_to_test = [
        (VulnClass.SQLI, "search.query_param", "1' OR '1'='1"),
        (VulnClass.COMMAND_INJECTION, "exec.ip", "127.0.0.1; whoami"),
        (VulnClass.XSS, "xss.name", "<script>alert(1)</script>"),
        (VulnClass.PATH_TRAVERSAL, "fi.page", "../../../../etc/passwd"),
    ]

    outcomes = []
    for vuln_class, injection_pt, known_payload in classes_to_test:
        genome = grammar_op.generate_initial_genome(
            vuln_class=vuln_class,
            injection_point=injection_pt,
            evasion_technique=EvasionTechnique.NONE,
        )
        genome.rendered_payload = known_payload
        result = client.fire(genome)

        fitness = combined_fitness(result.compromise_confidence, result.detector_confidence)
        descriptor = compute_behavior_descriptor(genome, result)
        outcome = archive.try_insert(genome, result, descriptor, fitness)
        outcomes.append(outcome)

    # Verify at least 3 distinct cells were created on real traffic
    new_cells = [o for o in outcomes if o == "new_cell"]
    assert len(new_cells) >= 3, f"Expected at least 3 new cells, got {len(new_cells)} from {outcomes}"
    assert len(archive.cells) >= 3
    assert archive.qd_score() > 1.0

    summary = archive.summary_for_llm()
    assert summary["total_filled_cells"] >= 3
