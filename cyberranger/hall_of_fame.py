from dataclasses import dataclass
from typing import Any, Optional
import uuid
import joblib

from cyberranger.features import extract_features
from cyberranger.genome import Genome


@dataclass
class HallOfFameEntry:
    """Historical record of retired red elites and blue detector snapshots (§3, §11)."""
    id: str
    entry_type: str            # "red_elite" | "blue_snapshot"
    genome: Optional[Genome]   # set if entry_type == "red_elite"
    blue_model_path: Optional[str]  # set if entry_type == "blue_snapshot"
    retired_at_generation: int
    confirmed_by: str          # triage reviewer identifier


class HallOfFame:
    """Regression archive and co-evolutionary regression runner (§11, §14)."""

    def __init__(self, persistence_store: Optional[Any] = None):
        self.entries: list[HallOfFameEntry] = []
        self.persistence = persistence_store

        if self.persistence:
            try:
                loaded = self.persistence.load_hall_of_fame_entries()
                if loaded:
                    self.entries.extend(loaded)
            except Exception:
                pass

    def archive_red_elite(
        self,
        genome: Genome,
        generation: int = 0,
        confirmed_by: str = "security_analyst",
    ) -> HallOfFameEntry:
        """Add a confirmed red elite exploit to the regression suite."""
        entry = HallOfFameEntry(
            id=str(uuid.uuid4()),
            entry_type="red_elite",
            genome=genome,
            blue_model_path=None,
            retired_at_generation=generation,
            confirmed_by=confirmed_by,
        )
        self.entries.append(entry)
        if self.persistence:
            try:
                self.persistence.save_hall_of_fame_entry(entry)
            except Exception:
                pass
        return entry

    def archive_blue_snapshot(
        self,
        model_path: str,
        generation: int = 0,
        confirmed_by: str = "orchestrator",
    ) -> HallOfFameEntry:
        """Add a trained blue detector snapshot to the regression suite."""
        entry = HallOfFameEntry(
            id=str(uuid.uuid4()),
            entry_type="blue_snapshot",
            genome=None,
            blue_model_path=str(model_path),
            retired_at_generation=generation,
            confirmed_by=confirmed_by,
        )
        self.entries.append(entry)
        if self.persistence:
            try:
                self.persistence.save_hall_of_fame_entry(entry)
            except Exception:
                pass
        return entry

    def get_red_elites(self) -> list[Genome]:
        return [e.genome for e in self.entries if e.entry_type == "red_elite" and e.genome is not None]

    def get_blue_snapshots(self) -> list[str]:
        return [e.blue_model_path for e in self.entries if e.entry_type == "blue_snapshot" and e.blue_model_path]

    def test_blue_against_all_red_elites(self, detector_client_or_model: Any) -> float:
        """Test current blue detector against all historical red elites.
        
        Returns the pass rate (fraction of historical attacks successfully flagged).
        """
        elites = self.get_red_elites()
        if not elites:
            return 1.0

        detected_count = 0
        for genome in elites:
            # Prepare payload representation
            req_data = {
                "url": f"/vulnerabilities/{genome.vuln_class.value}/",
                "params": {genome.injection_point: genome.rendered_payload},
                "body": genome.rendered_payload,
            }

            flagged = False
            # Check if detector is a sklearn classifier or wrapper model
            if hasattr(detector_client_or_model, "predict_proba"):
                feats = extract_features(req_data)
                proba = detector_client_or_model.predict_proba([feats])[0]
                mal_prob = float(proba[1]) if len(proba) > 1 else float(proba[0])
                flagged = mal_prob >= 0.5
            elif hasattr(detector_client_or_model, "predict"):
                res = detector_client_or_model.predict(req_data)
                flagged = res[0] if isinstance(res, tuple) else bool(res)
            elif isinstance(detector_client_or_model, str):
                # URL endpoint
                import requests
                try:
                    resp = requests.post(f"{detector_client_or_model.rstrip('/')}/detect", json=req_data, timeout=5)
                    flagged = resp.json().get("flagged", False)
                except Exception:
                    flagged = False

            if flagged:
                detected_count += 1

        return float(detected_count / len(elites))

    def test_population_against_retired_blue(
        self,
        population_genomes: list[Genome],
        retired_model_path: Optional[str] = None,
    ) -> float:
        """Test red population genomes against historical blue detector models.
        
        Returns the evasion pass rate (fraction of attacks that evade the retired detector).
        """
        if not population_genomes:
            return 0.0

        snapshots = self.get_blue_snapshots()
        target_path = retired_model_path or (snapshots[-1] if snapshots else None)
        if not target_path:
            return 1.0  # No historical detector to evade

        try:
            model = joblib.load(target_path)
        except Exception:
            return 1.0

        evaded_count = 0
        for genome in population_genomes:
            req_data = {
                "url": f"/vulnerabilities/{genome.vuln_class.value}/",
                "params": {genome.injection_point: genome.rendered_payload},
                "body": genome.rendered_payload,
            }
            feats = extract_features(req_data)
            proba = model.predict_proba([feats])[0]
            mal_prob = float(proba[1]) if len(proba) > 1 else float(proba[0])
            if mal_prob < 0.5:
                evaded_count += 1

        return float(evaded_count / len(population_genomes))
