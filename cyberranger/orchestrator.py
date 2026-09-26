from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
import yaml

from cyberranger.archive import Archive
from cyberranger.behavior import compute_behavior_descriptor
from cyberranger.blue_learner import BlueLearner
from cyberranger.hall_of_fame import HallOfFame
from cyberranger.metrics import MetricsLogger
from cyberranger.operators.bandit import OperatorBandit
from cyberranger.operators.crossover import CrossoverOperator
from cyberranger.operators.grammar import GrammarOperator
from cyberranger.operators.llm_semantic import LLMSemanticOperator
from cyberranger.persistence import PersistenceStore
from cyberranger.population import Population
from cyberranger.sandbox_client import SandboxClient
from cyberranger.scoring import combined_fitness
from cyberranger.triage import TriageQueue


@dataclass
class OrchestratorConfig:
    network_name: str = "cyberranger_internal"
    target_service: str = "dvwa-target"
    detector_service: str = "blue-detector"
    target_url: str = "http://127.0.0.1:8080"
    detector_url: str = "http://127.0.0.1:8000"
    offspring_per_gen: int = 4
    max_generations: int = 1000
    bandit_arms: list[str] = field(default_factory=lambda: ["grammar", "crossover", "llm_semantic"])
    learning_pass_interval: int = 10
    regression_floor: float = 0.9
    metrics_interval: int = 5
    scaling_check_interval: int = 20
    total_possible_cells: int = 375  # 5*5*5*3 from default config

    @classmethod
    def from_yaml(cls, yaml_path: Path | str) -> "OrchestratorConfig":
        with open(yaml_path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)

        archive_cfg = raw.get("archive", {})
        total_cells = (
            len(archive_cfg.get("vuln_classes", []))
            * len(archive_cfg.get("injection_point_categories", []))
            * len(archive_cfg.get("evasion_techniques", []))
            * len(archive_cfg.get("detector_outcomes", []))
        ) or 375

        return cls(
            network_name=raw.get("sandbox", {}).get("network_name", "cyberranger_internal"),
            target_service=raw.get("sandbox", {}).get("target_service", "dvwa-target"),
            detector_service=raw.get("sandbox", {}).get("detector_service", "blue-detector"),
            offspring_per_gen=raw.get("generation", {}).get("offspring_per_gen", 4),
            max_generations=raw.get("generation", {}).get("max_generations", 1000),
            bandit_arms=raw.get("bandit", {}).get("arms", ["grammar", "crossover", "llm_semantic"]),
            learning_pass_interval=raw.get("learning", {}).get("learning_pass_interval", 10),
            regression_floor=raw.get("learning", {}).get("regression_floor", 0.9),
            metrics_interval=raw.get("metrics", {}).get("metrics_interval", 5),
            scaling_check_interval=raw.get("metrics", {}).get("scaling_check_interval", 20),
            total_possible_cells=total_cells,
        )


class Orchestrator:
    """Main loop coordinator tying all components together (§11)."""

    def __init__(self, config: Optional[OrchestratorConfig] = None):
        self.config = config or OrchestratorConfig()
        self.persistence = PersistenceStore()
        self.archive = Archive(persistence_store=self.persistence)
        self.grammar_op = GrammarOperator()
        self.crossover_op = CrossoverOperator(self.grammar_op)
        self.llm_op = LLMSemanticOperator(grammar_operator=self.grammar_op)
        self.bandit = OperatorBandit(self.config.bandit_arms)
        self.population = Population(self.grammar_op)
        self.sandbox = SandboxClient(
            target_base_url=self.config.target_url,
            detector_base_url=self.config.detector_url,
            log_to_stdout=True,
        )
        self.triage_queue = TriageQueue(persistence_store=self.persistence)
        self.blue_learner = BlueLearner(detector_api_url=self.config.detector_url)
        self.hall_of_fame = HallOfFame(persistence_store=self.persistence)
        self.metrics = MetricsLogger()

    def load_checkpoint(self) -> Optional[int]:
        """Restore latest checkpoint from database into population and bandit."""
        latest_gen = self.persistence.load_latest_checkpoint(
            population=self.population,
            bandit=self.bandit,
        )
        if latest_gen is not None:
            print(f"[Orchestrator] Resumed from checkpoint generation {latest_gen}")
        return latest_gen


    def apply_operator(self, arm: str, parents: list) -> list:
        """Apply the selected mutation operator to produce offspring (§5, §11)."""
        offspring = []
        for p in parents:
            if arm == "grammar":
                child = self.grammar_op.mutate(p)
            elif arm == "crossover":
                other = self.population.sample_parents(self.archive, n=1)[0]
                child = self.crossover_op.crossover(p, other)
            elif arm == "llm_semantic":
                summary = self.archive.summary_for_llm()
                child = self.llm_op.mutate_from_archive(summary, parents=[p])
            else:
                child = self.grammar_op.mutate(p)
            offspring.append(child)
        return offspring

    def generation_step(self) -> dict[str, Any]:
        """Execute a single generation step (§11)."""
        arm = self.bandit.select()
        parents = self.population.sample_parents(self.archive, n=self.config.offspring_per_gen)
        offspring = self.apply_operator(arm, parents)

        step_events = []
        for genome in offspring:
            result = self.sandbox.fire(genome)
            fitness = combined_fitness(result.compromise_confidence, result.detector_confidence)
            descriptor = compute_behavior_descriptor(genome, result)
            outcome = self.archive.try_insert(genome, result, descriptor, fitness)

            # Reward mapping: new_cell -> 1.0, replaced_incumbent -> 0.3, rejected -> 0.0
            reward = {"new_cell": 1.0, "replaced_incumbent": 0.3, "rejected": 0.0}[outcome]
            self.bandit.update(arm, reward)

            triage_item = None
            if outcome != "rejected":
                triage_item = self.triage_queue.enqueue(genome, result, descriptor, outcome, fitness)

            step_events.append({
                "genome_id": genome.id,
                "vuln_class": genome.vuln_class.value,
                "operator": genome.operator_used,
                "payload": genome.rendered_payload,
                "outcome": outcome,
                "fitness": round(fitness, 3),
                "compromise_conf": result.compromise_confidence,
                "detector_flagged": result.detector_flagged,
                "triage_id": triage_item.id if triage_item else None,
            })

        self.population.advance_generation(offspring)
        self.persistence.checkpoint(self.population, self.bandit, generation=self.population.gen)

        return {
            "generation": self.population.gen,
            "arm_used": arm,
            "offspring_count": len(offspring),
            "events": step_events,
            "archive_coverage": self.archive.coverage(self.config.total_possible_cells),
            "qd_score": round(self.archive.qd_score(), 3),
        }

    def learning_pass(self) -> dict[str, Any]:
        """Execute blue detector retraining on confirmed triage items (§11)."""
        confirmed = self.triage_queue.pull_confirmed_since_last_pass()
        retrained = False
        model_path_str = None
        if confirmed:
            model, model_path = self.blue_learner.retrain(confirmed)
            model_path_str = str(model_path)
            self.hall_of_fame.archive_blue_snapshot(model_path_str, generation=self.population.gen)
            for item in confirmed:
                self.hall_of_fame.archive_red_elite(item.genome, generation=self.population.gen)
            retrained = True

        return {
            "retrained": retrained,
            "confirmed_count": len(confirmed),
            "model_path": model_path_str,
            "generation": self.population.gen,
        }

    def regression_pass(self) -> dict[str, Any]:
        """Execute regression tests and alert if blue detector drops below floor (§11)."""
        blue_pass_rate = self.hall_of_fame.test_blue_against_all_red_elites(self.config.detector_url)
        red_pass_rate = self.hall_of_fame.test_population_against_retired_blue(self.population.individuals)

        self.metrics.log(
            generation=self.population.gen,
            archive_coverage=self.archive.coverage(self.config.total_possible_cells),
            qd_score=self.archive.qd_score(),
            bandit_arm_weights=self.bandit.arm_weights(),
            blue_regression_pass_rate=blue_pass_rate,
            red_regression_pass_rate=red_pass_rate,
            pending_triage_count=len(self.triage_queue.list_items("pending")),
        )

        regressed = blue_pass_rate < self.config.regression_floor
        if regressed:
            print(
                f"[ALERT] Blue detector regressed against historical red techniques! "
                f"Pass rate {blue_pass_rate:.2f} < floor {self.config.regression_floor:.2f}"
            )

        return {
            "blue_regression_pass_rate": blue_pass_rate,
            "red_regression_pass_rate": red_pass_rate,
            "regressed": regressed,
            "regression_floor": self.config.regression_floor,
            "generation": self.population.gen,
        }


    def run(self, max_generations: Optional[int] = None):
        """Run the main co-evolutionary loop (§11)."""
        limit = max_generations if max_generations is not None else self.config.max_generations
        print(f"[Orchestrator] Starting run for {limit} generations...")

        for gen in range(limit):
            self.generation_step()

            if (gen + 1) % self.config.learning_pass_interval == 0:
                self.learning_pass()
                self.regression_pass()

            if (gen + 1) % self.config.metrics_interval == 0:
                self.metrics.log(
                    generation=self.population.gen,
                    archive_coverage=self.archive.coverage(self.config.total_possible_cells),
                    qd_score=self.archive.qd_score(),
                    bandit_arm_weights=self.bandit.arm_weights(),
                    pending_triage_count=len(self.triage_queue.list_items("pending")),
                )

            if (gen + 1) % self.config.scaling_check_interval == 0:
                if self.metrics.coverage_has_plateaued():
                    print("[NOTICE] Archive coverage has plateaued — consider increasing target complexity")
