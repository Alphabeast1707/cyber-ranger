"""Tests for Milestone 3 (§14):
- Genome and TrialResult data schemas
- Grammar mutation operator
- sandbox_client.fire() dispatching payloads, scoring, and logging to stdout
"""

import pytest

from cyberranger.genome import EvasionTechnique, Genome, TrialResult, VulnClass
from cyberranger.operators.grammar import GrammarOperator
from cyberranger.sandbox_client import SandboxClient


def test_genome_dataclass_and_serialization():
    """Verify Genome dataclass fields, defaults, and dictionary serialization."""
    g = Genome(
        vuln_class=VulnClass.SQLI,
        injection_point="login.username",
        evasion_technique=EvasionTechnique.ENCODING,
        payload_template="' OR <condition>--",
        rendered_payload="' OR 1=1--",
    )
    assert g.id is not None
    assert g.generation == 0
    assert g.vuln_class == VulnClass.SQLI

    # Serialization roundtrip
    d = g.to_dict()
    assert d["vuln_class"] == "sqli"
    assert d["evasion_technique"] == "encoding"

    g_restored = Genome.from_dict(d)
    assert g_restored.id == g.id
    assert g_restored.vuln_class == VulnClass.SQLI
    assert g_restored.evasion_technique == EvasionTechnique.ENCODING


def test_trial_result_dataclass_and_serialization():
    """Verify TrialResult dataclass and serialization."""
    tr = TrialResult(
        genome_id="test-id-123",
        target_compromised=True,
        compromise_confidence=0.95,
        detector_flagged=False,
        detector_confidence=0.0,
        detector_rule_fired=None,
        response_signature="abc123hash",
        latency_ms=45,
        raw_response_excerpt="<html>Welcome admin</html>",
    )
    assert tr.target_compromised is True
    assert tr.compromise_confidence == 0.95

    tr_dict = tr.to_dict()
    assert tr_dict["genome_id"] == "test-id-123"

    tr_restored = TrialResult.from_dict(tr_dict)
    assert tr_restored.genome_id == "test-id-123"
    assert tr_restored.target_compromised is True


def test_grammar_operator_generation_and_mutation():
    """Verify GrammarOperator creates and mutates structural payloads."""
    grammar_op = GrammarOperator()

    for vuln in VulnClass:
        g = grammar_op.generate_initial_genome(vuln)
        assert g.vuln_class == vuln
        assert g.rendered_payload != ""
        # Ensure no unexpanded grammar symbols like <start>, <boundary>, <operator>, etc.
        unexpanded = [sym for sym in grammar_op.grammars.get(vuln.value, {}).keys() if f"<{sym}>" in g.rendered_payload]
        assert not unexpanded, f"Unexpanded symbols found: {unexpanded}"

        # Mutate
        mutated = grammar_op.mutate(g)
        assert mutated.generation == g.generation + 1
        assert mutated.parent_ids == [g.id]
        assert mutated.operator_used == "grammar"
        assert mutated.rendered_payload != ""


def test_grammar_operator_evasion_techniques():
    """Verify grammar operator evasion techniques apply transformations."""
    grammar_op = GrammarOperator()
    raw = "' OR 1=1 --"

    # URL Encoding
    encoded, detail = grammar_op.apply_evasion(raw, EvasionTechnique.ENCODING)
    assert "%20" in encoded or "%27" in encoded

    # Comment injection
    commented, detail = grammar_op.apply_evasion(raw, EvasionTechnique.COMMENT_INJECTION)
    assert "/**/" in commented

    # Case variation
    cased, detail = grammar_op.apply_evasion("union select", EvasionTechnique.CASE_VARIATION)
    assert cased != ""


def test_sandbox_client_fire_against_dvwa_and_blue_detector(capsys):
    """Verify sandbox_client.fire() fires payloads, mirrors to blue detector, and logs to stdout."""
    client = SandboxClient(
        target_base_url="http://127.0.0.1:8080",
        detector_base_url="http://127.0.0.1:8000",
        log_to_stdout=True,
    )
    grammar_op = GrammarOperator()

    # Generate a SQLi payload
    genome = grammar_op.generate_initial_genome(
        vuln_class=VulnClass.SQLI,
        injection_point="search.query_param",
    )
    # Ensure a known effective payload for the test
    genome.rendered_payload = "1' OR '1'='1"

    # Fire
    result = client.fire(genome)

    # Verify TrialResult
    assert isinstance(result, TrialResult)
    assert result.genome_id == genome.id
    assert result.target_compromised is True
    assert result.compromise_confidence > 0.5
    assert result.latency_ms > 0
    assert result.response_signature != ""
    assert isinstance(result.detector_flagged, bool)
    assert isinstance(result.detector_confidence, float)

    # Verify logged to stdout
    captured = capsys.readouterr()
    assert "[SandboxClient]" in captured.out
    assert "Fired Genome" in captured.out
    assert "Compromised=True" in captured.out
