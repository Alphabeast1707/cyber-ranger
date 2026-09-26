"""Tests for Milestone 6 (§14):
- Crossover operator (§5)
- LLM semantic mutation operator and downstream deterministic renderer (§5)
"""

from unittest.mock import MagicMock
import pytest

from cyberranger.archive import Archive
from cyberranger.genome import EvasionTechnique, Genome, VulnClass
from cyberranger.operators.crossover import CrossoverOperator
from cyberranger.operators.grammar import GrammarOperator
from cyberranger.operators.llm_semantic import LLMSemanticOperator, propose_new_strategy


def test_crossover_operator():
    """Verify CrossoverOperator splices templates and produces valid offspring."""
    grammar_op = GrammarOperator()
    crossover_op = CrossoverOperator(grammar_op)

    p1 = Genome(
        vuln_class=VulnClass.SQLI,
        injection_point="search.query",
        evasion_technique=EvasionTechnique.NONE,
        payload_template="' OR 1=1 --",
        rendered_payload="' OR 1=1 --",
        generation=1,
    )
    p2 = Genome(
        vuln_class=VulnClass.SQLI,
        injection_point="search.query",
        evasion_technique=EvasionTechnique.ENCODING,
        payload_template="' UNION SELECT 1, 2 #",
        rendered_payload="' UNION SELECT 1, 2 #",
        generation=2,
    )

    child = crossover_op.crossover(p1, p2)

    assert child.operator_used == "crossover"
    assert child.generation == 3
    assert set(child.parent_ids) == {p1.id, p2.id}
    assert child.rendered_payload != ""
    assert child.vuln_class == VulnClass.SQLI


def test_llm_semantic_proposal_with_mock_client():
    """Verify propose_new_strategy parses JSON output from Anthropic client properly."""
    mock_client = MagicMock()
    mock_message = MagicMock()
    mock_message.content = [MagicMock(text="""{
        "vuln_class": "sqli",
        "injection_point_category": "auth_form",
        "evasion_technique": "comment_injection",
        "structural_description": "Inline comment bypass around UNION SELECT tokens",
        "rationale": "Bypasses naive token filters that look for whitespace"
    }""")]
    mock_client.messages.create.return_value = mock_message

    archive = Archive()
    summary = archive.summary_for_llm()

    proposal = propose_new_strategy(summary, client=mock_client, model="claude-sonnet-4-6")
    assert proposal["vuln_class"] == "sqli"
    assert proposal["injection_point_category"] == "auth_form"
    assert proposal["evasion_technique"] == "comment_injection"
    assert "Inline comment" in proposal["structural_description"]


def test_llm_semantic_operator_downstream_renderer():
    """Verify LLMSemanticOperator uses downstream deterministic renderer to produce Genome."""
    mock_client = MagicMock()
    mock_message = MagicMock()
    mock_message.content = [MagicMock(text="""{
        "vuln_class": "command_injection",
        "injection_point_category": "url_param",
        "evasion_technique": "whitespace_substitution",
        "structural_description": "Substituted whitespace in command separator chain",
        "rationale": "Explores under-represented command injection cell"
    }""")]
    mock_client.messages.create.return_value = mock_message

    operator = LLMSemanticOperator(client=mock_client)
    archive = Archive()
    summary = archive.summary_for_llm()

    parent = Genome(vuln_class=VulnClass.COMMAND_INJECTION, generation=4)
    offspring = operator.mutate_from_archive(summary, parents=[parent])

    assert offspring.operator_used == "llm_semantic"
    assert offspring.vuln_class == VulnClass.COMMAND_INJECTION
    assert offspring.generation == 5
    assert offspring.parent_ids == [parent.id]
    assert offspring.rendered_payload != ""
    assert offspring.metadata["llm_model"] == "claude-sonnet-4-6"


def test_llm_semantic_offline_fallback():
    """Verify LLMSemanticOperator works in offline/fallback mode without external API."""
    operator = LLMSemanticOperator(client=None)
    archive = Archive()
    summary = archive.summary_for_llm()

    genome = operator.mutate_from_archive(summary)
    assert genome.operator_used == "llm_semantic"
    assert genome.rendered_payload != ""
    assert isinstance(genome.vuln_class, VulnClass)
