import random
from typing import Optional

from cyberranger.archive import Archive
from cyberranger.genome import EvasionTechnique, Genome, VulnClass
from cyberranger.operators.grammar import GrammarOperator


class Population:
    """Manages the red agent population and parent selection (§11)."""

    def __init__(self, grammar_operator: Optional[GrammarOperator] = None, max_size: int = 100):
        self.gen = 0
        self.individuals: list[Genome] = []
        self.grammar = grammar_operator or GrammarOperator()
        self.max_size = max_size
        self._initialize_seeds()

    def _initialize_seeds(self):
        """Seed population with baseline genomes across all vulnerability classes."""
        for vuln in VulnClass:
            g = self.grammar.generate_initial_genome(vuln, injection_point="default.param")
            self.individuals.append(g)

    def sample_parents(self, archive: Optional[Archive] = None, n: int = 1) -> list[Genome]:
        """Sample parent genomes preferentially from the MAP-Elites archive (§5, §11)."""
        pool: list[Genome] = []

        if archive and archive.cells:
            # Sample genomes stored in archive cells
            for genome, _, _ in archive.cells.values():
                pool.append(genome)

        if not pool:
            pool = self.individuals

        if not pool:
            # Fallback to generating a fresh genome
            g = self.grammar.generate_initial_genome(VulnClass.SQLI)
            return [g] * n

        return [random.choice(pool) for _ in range(n)]

    def advance_generation(self, offspring: list[Genome]):
        """Advance generation counter and incorporate offspring into active population."""
        self.gen += 1
        self.individuals.extend(offspring)
        # Keep most recent individuals up to max_size
        if len(self.individuals) > self.max_size:
            self.individuals = self.individuals[-self.max_size:]
