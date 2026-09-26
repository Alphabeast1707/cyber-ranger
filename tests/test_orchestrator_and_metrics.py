"""Tests for Milestone 10 (§14):
- Metrics logging to JSON lines (§13)
- Plateau detection check (§11, §14)
- End-to-end Orchestrator generation loop, persistence, and triage integration
"""

import pytest

from cyberranger.metrics import MetricsLogger
from cyberranger.orchestrator import Orchestrator, OrchestratorConfig
from cyberranger.persistence import PersistenceStore


def test_metrics_logging_and_history(tmp_path):
    """Verify metrics logging to JSON-lines file."""
    metrics_file = tmp_path / "test_metrics.jsonl"
    logger = MetricsLogger(log_path=metrics_file)

    logger.log(
        generation=1,
        archive_coverage=0.05,
        qd_score=1.2,
        bandit_arm_weights={"grammar": 1.0, "crossover": 0.3},
        blue_regression_pass_rate=1.0,
        red_regression_pass_rate=0.8,
        pending_triage_count=2,
    )
    logger.log(
        generation=2,
        archive_coverage=0.08,
        qd_score=2.1,
        bandit_arm_weights={"grammar": 0.9, "crossover": 0.5},
        blue_regression_pass_rate=1.0,
        red_regression_pass_rate=0.85,
        pending_triage_count=3,
    )

    assert metrics_file.exists()
    records = logger.load_history()
    assert len(records) == 2
    assert records[0]["generation"] == 1
    assert records[1]["archive_coverage"] == 0.08


def test_plateau_detection_logic():
    """Verify coverage plateau detection triggers only when coverage growth stagnates."""
    logger = MetricsLogger()

    # Dynamic growth -> not plateaued
    for i in range(5):
        logger.log(generation=i, archive_coverage=i * 0.02)
    assert logger.coverage_has_plateaued(window_size=5, min_delta=0.01) is False

    # Stagnant growth -> plateaued
    for i in range(5, 12):
        logger.log(generation=i, archive_coverage=0.10)
    assert logger.coverage_has_plateaued(window_size=5, min_delta=0.01) is True


def test_orchestrator_generation_step_and_checkpoint(tmp_path):
    """Verify Orchestrator runs generation steps, logs to stdout, and checkpoints to SQLite."""
    db_file = tmp_path / "test_checkpoints.db"
    metrics_file = tmp_path / "test_orchestrator_metrics.jsonl"

    cfg = OrchestratorConfig(
        target_url="http://127.0.0.1:8080",
        detector_url="http://127.0.0.1:8000",
        offspring_per_gen=2,
        max_generations=2,
        learning_pass_interval=1,
        metrics_interval=1,
    )
    orchestrator = Orchestrator(cfg)
    orchestrator.persistence = PersistenceStore(db_path=db_file)
    orchestrator.metrics = MetricsLogger(log_path=metrics_file)

    # Run 2 generation steps
    orchestrator.run(max_generations=2)

    assert orchestrator.population.gen == 2
    assert len(orchestrator.archive.cells) > 0
    assert db_file.exists()

    # Verify checkpoint can be reloaded
    restored_gen = orchestrator.persistence.load_latest_checkpoint()
    assert restored_gen == 2

    # Verify triage items were enqueued
    triage_items = orchestrator.triage_queue.list_items()
    assert len(triage_items) > 0
