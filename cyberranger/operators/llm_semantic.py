import json
import os
import random
import re
from typing import Any, Optional

from cyberranger.genome import EvasionTechnique, Genome, VulnClass
from cyberranger.operators.grammar import GrammarOperator

SYSTEM_PROMPT = """You are proposing new attack STRUCTURES (not payloads) for an
authorized security research system attacking an isolated, intentionally-vulnerable
DVWA instance. Given the current archive coverage (which vulnerability classes,
injection points, and evasion technique combinations are already well-explored),
propose a new structural approach not yet represented. Output JSON only:
{"vuln_class": ..., "injection_point_category": ..., "evasion_technique": ...,
 "structural_description": "abstract description of the technique, no literal payload",
 "rationale": "why this is likely to be a distinct niche from what's covered"}
"""


def parse_json(text: str) -> dict[str, Any]:
    """Extract JSON object from LLM response text."""
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        return json.loads(match.group(0))
    return json.loads(text)


def propose_new_strategy(
    archive_summary: dict[str, Any],
    client: Optional[Any] = None,
    model: str = "claude-sonnet-4-6",
) -> dict[str, Any]:
    """Call LLM API to propose an abstract structural attack strategy (§5).
    
    If client is provided or ANTHROPIC_API_KEY is available, calls Anthropic API.
    Otherwise, falls back to a deterministic heuristic explorer for under-explored niches.
    """
    if client is not None or os.environ.get("ANTHROPIC_API_KEY"):
        if client is None:
            import anthropic
            client = anthropic.Anthropic()

        response = client.messages.create(
            model=model,
            max_tokens=500,
            system=SYSTEM_PROMPT,
            messages=[{
                "role": "user",
                "content": f"Current archive coverage:\n{json.dumps(archive_summary, indent=2)}",
            }],
        )
        return parse_json(response.content[0].text)

    # Offline / Test fallback: identify under-explored combinations
    explored_combos = set(archive_summary.get("distribution", {}).keys())
    all_vulns = [v.value for v in VulnClass]
    all_categories = ["auth_form", "search", "url_param", "file_upload", "cookie"]
    all_evasions = [e.value for e in EvasionTechnique]

    unexplored = []
    for v in all_vulns:
        for c in all_categories:
            for e in all_evasions:
                combo = f"{v}:{c}:{e}"
                if combo not in explored_combos:
                    unexplored.append((v, c, e))

    if unexplored:
        chosen_v, chosen_c, chosen_e = random.choice(unexplored)
    else:
        chosen_v = random.choice(all_vulns)
        chosen_c = random.choice(all_categories)
        chosen_e = random.choice(all_evasions)

    return {
        "vuln_class": chosen_v,
        "injection_point_category": chosen_c,
        "evasion_technique": chosen_e,
        "structural_description": f"Targeted boundary injection with {chosen_e} evasion for {chosen_v}",
        "rationale": "Generated to explore under-represented niche in current MAP-Elites archive",
    }


class LLMSemanticOperator:
    """LLM semantic mutation operator with downstream deterministic renderer (§5)."""

    def __init__(
        self,
        client: Optional[Any] = None,
        model: str = "claude-sonnet-4-6",
        grammar_operator: Optional[GrammarOperator] = None,
    ):
        self.client = client
        self.model = model
        self.grammar = grammar_operator or GrammarOperator()

    def mutate_from_archive(
        self,
        archive_summary: dict[str, Any],
        parents: Optional[list[Genome]] = None,
    ) -> Genome:
        """Propose a new strategy using LLM and render it down deterministically into an executable Genome."""
        proposal = propose_new_strategy(archive_summary, self.client, self.model)

        # Parse vuln_class and evasion
        try:
            vuln_class = VulnClass(proposal.get("vuln_class", "sqli"))
        except ValueError:
            vuln_class = VulnClass.SQLI

        try:
            evasion = EvasionTechnique(proposal.get("evasion_technique", "none"))
        except ValueError:
            evasion = EvasionTechnique.SEMANTIC_REWRITE

        category = proposal.get("injection_point_category", "search")
        structural_desc = proposal.get("structural_description", "")
        rationale = proposal.get("rationale", "")

        # Downstream deterministic renderer reusing grammar expansion logic
        parent_id = parents[0].id if parents else None
        generation = (parents[0].generation + 1) if parents else 0

        rules = self.grammar.grammars.get(vuln_class.value, {})
        start_templates = rules.get("start", [""])
        template = random.choice(start_templates) if start_templates else ""
        rendered = self.grammar.expand_template(template, rules)
        rendered, detail = self.grammar.apply_evasion(rendered, evasion)

        return Genome(
            generation=generation,
            parent_ids=[parent_id] if parent_id else [],
            operator_used="llm_semantic",
            vuln_class=vuln_class,
            injection_point=f"{category}.param",
            evasion_technique=evasion,
            evasion_technique_detail=structural_desc or detail,
            payload_template=template,
            rendered_payload=rendered,
            metadata={
                "structural_description": structural_desc,
                "rationale": rationale,
                "llm_model": self.model,
            },
        )
