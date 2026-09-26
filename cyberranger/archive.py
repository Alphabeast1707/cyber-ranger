from collections import Counter
from typing import Any, Optional
from cyberranger.genome import BehaviorDescriptor, Genome, TrialResult


class Archive:
    """MAP-Elites quality-diversity archive (§8)."""

    def __init__(self, persistence_store: Optional[Any] = None):
        # cell_key -> (Genome, TrialResult, fitness)
        self.cells: dict[tuple, tuple[Genome, TrialResult, float]] = {}
        self.persistence = persistence_store

        if self.persistence:
            try:
                loaded = self.persistence.load_archive_cells()
                if loaded:
                    self.cells.update(loaded)
            except Exception:
                pass

    def try_insert(
        self,
        genome: Genome,
        result: TrialResult,
        descriptor: BehaviorDescriptor,
        fitness: float,
    ) -> str:
        """Returns 'new_cell', 'replaced_incumbent', or 'rejected'."""
        key = descriptor.cell_key()
        if key not in self.cells:
            self.cells[key] = (genome, result, float(fitness))
            if self.persistence:
                try:
                    self.persistence.save_archive_cell(key, genome, result, fitness)
                except Exception:
                    pass
            return "new_cell"

        _, _, incumbent_fitness = self.cells[key]
        if fitness > incumbent_fitness:
            self.cells[key] = (genome, result, float(fitness))
            if self.persistence:
                try:
                    self.persistence.save_archive_cell(key, genome, result, fitness)
                except Exception:
                    pass
            return "replaced_incumbent"

        return "rejected"

    def coverage(self, total_possible_cells: int) -> float:
        if total_possible_cells <= 0:
            return 0.0
        return len(self.cells) / total_possible_cells

    def qd_score(self) -> float:
        return sum(fitness for _, _, fitness in self.cells.values())

    def get_matrix_data(self) -> list[dict[str, Any]]:
        """Return structured cell data for MAP-Elites grid visualization in the UI."""
        matrix = []
        for key, (genome, result, fitness) in self.cells.items():
            vuln_class, injection_cat, evasion_tech, detector_outcome = key
            matrix.append({
                "vuln_class": getattr(vuln_class, "value", str(vuln_class)),
                "injection_point_category": getattr(injection_cat, "value", str(injection_cat)),
                "evasion_technique": getattr(evasion_tech, "value", str(evasion_tech)),
                "detector_outcome": getattr(detector_outcome, "value", str(detector_outcome)),
                "fitness": round(fitness, 3),
                "genome_id": genome.id,
                "payload": genome.rendered_payload,
                "template": genome.payload_template,
                "compromise_confidence": result.compromise_confidence,
                "detector_confidence": result.detector_confidence,
                "latency_ms": result.latency_ms,
            })
        return matrix

    def summary_for_llm(self) -> dict[str, Any]:
        """Coarsened view of filled cells, for the LLM semantic mutator's prompt —
        counts per vuln_class/evasion_technique combo, not raw payloads."""
        counts: Counter[str] = Counter()
        explored_combos = []

        for key, (genome, _, fitness) in self.cells.items():
            vuln_class, injection_cat, evasion_tech, detector_outcome = key
            vc_str = getattr(vuln_class, "value", str(vuln_class))
            ic_str = getattr(injection_cat, "value", str(injection_cat))
            et_str = getattr(evasion_tech, "value", str(evasion_tech))
            do_str = getattr(detector_outcome, "value", str(detector_outcome))
            combo_str = f"{vc_str}:{ic_str}:{et_str}"
            counts[combo_str] += 1
            explored_combos.append({
                "vuln_class": vc_str,
                "injection_point_category": ic_str,
                "evasion_technique": et_str,
                "detector_outcome": do_str,
                "fitness": round(fitness, 3),
            })


        return {
            "total_filled_cells": len(self.cells),
            "qd_score": round(self.qd_score(), 3),
            "distribution": dict(counts),
            "explored_cells": explored_combos,
        }

