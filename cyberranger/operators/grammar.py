import json
from pathlib import Path
import random
import re
from typing import Optional
import urllib.parse

from cyberranger.genome import EvasionTechnique, Genome, VulnClass

DEFAULT_FIXTURES_PATH = Path(__file__).resolve().parent.parent / "fixtures" / "dvwa_grammars.json"


class GrammarOperator:
    """BNF-style grammar mutation operator (§5).
    
    Expands structural grammar rules rather than fixed string lists,
    allowing target-specific grammars to live in fixtures without modifying operator code.
    """

    def __init__(self, fixtures_path: Optional[Path | str] = None):
        self.fixtures_path = Path(fixtures_path) if fixtures_path else DEFAULT_FIXTURES_PATH
        self.grammars = self._load_grammars()

    def _load_grammars(self) -> dict:
        if not self.fixtures_path.exists():
            raise FileNotFoundError(f"Grammar fixtures not found at {self.fixtures_path}")
        with open(self.fixtures_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def expand_template(self, template: str, rules: dict, max_depth: int = 5) -> str:
        """Recursively expand non-terminal symbols <symbol> in template."""
        result = template
        for _ in range(max_depth):
            symbols = re.findall(r"<([a-zA-Z0-9_\-]+)>", result)
            if not symbols:
                break
            for sym in symbols:
                if sym in rules and rules[sym]:
                    replacement = random.choice(rules[sym])
                    result = result.replace(f"<{sym}>", replacement, 1)
                else:
                    result = result.replace(f"<{sym}>", "", 1)
        return result

    def generate_initial_genome(
        self,
        vuln_class: VulnClass,
        injection_point: str = "default.param",
        evasion_technique: EvasionTechnique = EvasionTechnique.NONE,
    ) -> Genome:
        """Create a new seed Genome expanded from the grammar."""
        vuln_key = vuln_class.value
        rules = self.grammars.get(vuln_key, {})
        start_templates = rules.get("start", [""])
        template = random.choice(start_templates) if start_templates else ""
        rendered = self.expand_template(template, rules)
        rendered, detail = self.apply_evasion(rendered, evasion_technique)

        return Genome(
            operator_used="grammar",
            vuln_class=vuln_class,
            injection_point=injection_point,
            evasion_technique=evasion_technique,
            evasion_technique_detail=detail,
            payload_template=template,
            rendered_payload=rendered,
        )

    def apply_evasion(
        self,
        payload: str,
        technique: EvasionTechnique,
    ) -> tuple[str, Optional[str]]:
        """Apply an evasion transformation to the rendered payload."""
        if technique == EvasionTechnique.NONE:
            return payload, None

        if technique == EvasionTechnique.ENCODING:
            # URL-encode or partially URL-encode
            encoded = urllib.parse.quote(payload)
            return encoded, "url_encoded"

        if technique == EvasionTechnique.CASE_VARIATION:
            # Randomize casing of alphabetic characters
            varied = "".join(
                c.upper() if random.random() > 0.5 else c.lower() for c in payload
            )
            return varied, "random_casing"

        if technique == EvasionTechnique.COMMENT_INJECTION:
            # Inject SQL/Shell comment tokens into spaces or keywords
            injected = payload.replace(" ", "/**/")
            return injected, "inline_comment_injection"

        if technique == EvasionTechnique.WHITESPACE_SUBSTITUTION:
            # Substitute space with + or tab or newline
            sub_char = random.choice(["+", "%09", "%0a", "/**/"])
            subbed = payload.replace(" ", sub_char)
            return subbed, f"whitespace_substituted_with_{sub_char}"

        if technique == EvasionTechnique.SEMANTIC_REWRITE:
            # For semantic rewrite, provide structured variation
            return f"/*semantic*/ {payload}", "semantic_prefix"

        return payload, None

    def mutate(self, parent: Genome) -> Genome:
        """Mutate an existing Genome by picking a production rule or evasion variation."""
        vuln_key = parent.vuln_class.value
        rules = self.grammars.get(vuln_key, {})

        # Decision: mutate template production, re-expand, or mutate evasion technique
        mutation_mode = random.choice(["template", "re_expand", "evasion"])

        new_template = parent.payload_template
        new_evasion = parent.evasion_technique

        if mutation_mode == "template" or not new_template:
            start_templates = rules.get("start", [""])
            new_template = random.choice(start_templates) if start_templates else ""

        if mutation_mode == "evasion":
            available_evasions = [
                EvasionTechnique.NONE,
                EvasionTechnique.ENCODING,
                EvasionTechnique.CASE_VARIATION,
                EvasionTechnique.COMMENT_INJECTION,
                EvasionTechnique.WHITESPACE_SUBSTITUTION,
            ]
            new_evasion = random.choice(available_evasions)

        rendered = self.expand_template(new_template, rules)
        rendered, detail = self.apply_evasion(rendered, new_evasion)

        return Genome(
            generation=parent.generation + 1,
            parent_ids=[parent.id],
            operator_used="grammar",
            vuln_class=parent.vuln_class,
            injection_point=parent.injection_point,
            evasion_technique=new_evasion,
            evasion_technique_detail=detail,
            payload_template=new_template,
            rendered_payload=rendered,
            metadata={"parent_generation": parent.generation},
        )
