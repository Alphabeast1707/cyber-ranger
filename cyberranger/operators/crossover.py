import random
import re
from typing import Optional

from cyberranger.genome import Genome
from cyberranger.operators.grammar import GrammarOperator


class CrossoverOperator:
    """Genetic crossover operator (§5).
    
    Splices the payload_template structures of two parent genomes
    at a compatible boundary point and renders offspring.
    """

    def __init__(self, grammar_operator: Optional[GrammarOperator] = None):
        self.grammar = grammar_operator or GrammarOperator()

    def crossover(self, parent1: Genome, parent2: Genome) -> Genome:
        """Splice payload templates of two parents at a compatible boundary point."""
        t1 = parent1.payload_template or parent1.rendered_payload
        t2 = parent2.payload_template or parent2.rendered_payload

        # Attempt to split on standard payload tokens: whitespace, operators, boundaries
        split_pattern = r"(\s+|OR|AND|;|--|\/\*|\*\/)"
        tokens1 = [t for t in re.split(split_pattern, t1) if t]
        tokens2 = [t for t in re.split(split_pattern, t2) if t]

        if len(tokens1) > 1 and len(tokens2) > 1:
            cut1 = random.randint(1, len(tokens1) - 1)
            cut2 = random.randint(1, len(tokens2) - 1)
            child_template = "".join(tokens1[:cut1]) + "".join(tokens2[cut2:])
        else:
            # Fallback: simple character midpoint splice or template choice
            cut1 = len(t1) // 2
            cut2 = len(t2) // 2
            child_template = t1[:cut1] + t2[cut2:]

        # Inherit vuln_class and injection_point preferentially from parent1
        vuln_class = parent1.vuln_class
        injection_point = parent1.injection_point
        evasion_tech = random.choice([parent1.evasion_technique, parent2.evasion_technique])

        # Render downstream using grammar expansion logic
        rules = self.grammar.grammars.get(vuln_class.value, {})
        rendered = self.grammar.expand_template(child_template, rules)
        rendered, detail = self.grammar.apply_evasion(rendered, evasion_tech)

        return Genome(
            generation=max(parent1.generation, parent2.generation) + 1,
            parent_ids=[parent1.id, parent2.id],
            operator_used="crossover",
            vuln_class=vuln_class,
            injection_point=injection_point,
            evasion_technique=evasion_tech,
            evasion_technique_detail=detail or parent1.evasion_technique_detail,
            payload_template=child_template,
            rendered_payload=rendered,
            metadata={"crossover_parents": [parent1.id, parent2.id]},
        )
