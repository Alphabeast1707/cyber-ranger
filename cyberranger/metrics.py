from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Optional


class MetricsLogger:
    """Logs system metrics to JSON lines (metrics.jsonl) and tracks archive plateau (§13)."""

    def __init__(self, log_path: Optional[Path | str] = None):
        self.log_path = Path(log_path) if log_path else Path("metrics.jsonl")
        self.history: list[dict[str, Any]] = []

    def log(
        self,
        generation: int = 0,
        archive_coverage: float = 0.0,
        qd_score: float = 0.0,
        bandit_arm_weights: Optional[dict[str, float]] = None,
        blue_regression_pass_rate: float = 1.0,
        red_regression_pass_rate: float = 1.0,
        mean_episodes_to_first_compromise_per_class: Optional[dict[str, float]] = None,
        pending_triage_count: int = 0,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Log a snapshot record to JSON-lines metrics store (§13)."""
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "generation": int(generation),
            "archive_coverage": round(float(archive_coverage), 4),
            "qd_score": round(float(qd_score), 4),
            "bandit_arm_weights": bandit_arm_weights or {},
            "blue_regression_pass_rate": round(float(blue_regression_pass_rate), 4),
            "red_regression_pass_rate": round(float(red_regression_pass_rate), 4),
            "mean_episodes_to_first_compromise_per_class": mean_episodes_to_first_compromise_per_class or {},
            "pending_triage_count": int(pending_triage_count),
        }
        record.update(kwargs)

        self.history.append(record)

        # Append to jsonl file
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

        return record

    def load_history(self) -> list[dict[str, Any]]:
        """Load history from log file if present."""
        if not self.log_path.exists():
            return self.history
        records = []
        with open(self.log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        self.history = records
        return records

    def coverage_has_plateaued(self, window_size: int = 5, min_delta: float = 0.005) -> bool:
        """Check whether archive coverage has plateaued over recent evaluations (§11, §14).
        
        Returns True if the difference between maximum and minimum coverage
        in the last window_size observations is less than min_delta.
        """
        if len(self.history) < window_size:
            return False

        recent = self.history[-window_size:]
        coverages = [r.get("archive_coverage", 0.0) for r in recent]
        delta = max(coverages) - min(coverages)
        return delta < min_delta
