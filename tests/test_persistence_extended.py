"""Tests for extended SQLite persistence layer (§2, §8, §9, §11)."""

import pytest
from cyberranger.genome import BehaviorDescriptor, EvasionTechnique, Genome, TrialResult, VulnClass
from cyberranger.hall_of_fame import HallOfFame, HallOfFameEntry
from cyberranger.persistence import PersistenceStore
from cyberranger.triage import TriageItem, TriageQueue
from cyberranger.archive import Archive


@pytest.fixture
def temp_db(tmp_path):
    return tmp_path / "extended_test.db"


def test_triage_item_sqlite_persistence(temp_db):
    store = PersistenceStore(db_path=temp_db)
    queue = TriageQueue(persistence_store=store)

    g = Genome(vuln_class=VulnClass.SQLI, payload_template="' OR 1=1--", rendered_payload="' OR 1=1--")
    tr = TrialResult(
        genome_id=g.id,
        target_compromised=True,
        compromise_confidence=0.95,
        detector_flagged=False,
        detector_confidence=0.0,
        detector_rule_fired=None,
        response_signature="sig_persist_1",
        latency_ms=12,
        raw_response_excerpt="admin dump",
    )
    bd = BehaviorDescriptor(
        vuln_class=VulnClass.SQLI,
        injection_point_category="auth_form",
        evasion_technique=EvasionTechnique.NONE,
        detector_outcome="undetected",
    )

    # 1. Enqueue persists to SQLite
    item = queue.enqueue(g, tr, bd, archive_cell_status="new_cell", fitness=0.95)
    assert item.status == "pending"

    # 2. Fresh queue instance loads item from SQLite
    queue_reloaded = TriageQueue(persistence_store=store)
    loaded_item = queue_reloaded.get(item.id)
    assert loaded_item is not None
    assert loaded_item.genome.rendered_payload == "' OR 1=1--"
    assert loaded_item.status == "pending"

    # 3. Update status persists
    queue_reloaded.update_status(item.id, "confirmed", reviewer_note="Verified by analyst", reviewer_id="analyst_bob")

    queue_reloaded_2 = TriageQueue(persistence_store=store)
    confirmed_item = queue_reloaded_2.get(item.id)
    assert confirmed_item.status == "confirmed"
    assert confirmed_item.reviewer_note == "Verified by analyst"


def test_archive_cells_sqlite_persistence(temp_db):
    store = PersistenceStore(db_path=temp_db)
    archive = Archive(persistence_store=store)

    g = Genome(vuln_class=VulnClass.XSS, payload_template="<script>alert(1)</script>", rendered_payload="<script>alert(1)</script>")
    tr = TrialResult(
        genome_id=g.id,
        target_compromised=True,
        compromise_confidence=0.9,
        detector_flagged=True,
        detector_confidence=0.85,
        detector_rule_fired="rule_xss",
        response_signature="sig_xss",
        latency_ms=8,
        raw_response_excerpt="<script>alert(1)</script>",
    )
    bd = BehaviorDescriptor(
        vuln_class=VulnClass.XSS,
        injection_point_category="search",
        evasion_technique=EvasionTechnique.COMMENT_INJECTION,
        detector_outcome="flagged_high_confidence",
    )

    # 1. Insert cell
    outcome = archive.try_insert(g, tr, bd, fitness=0.75)
    assert outcome == "new_cell"
    assert len(archive.cells) == 1

    # 2. Reload in fresh archive
    archive_reloaded = Archive(persistence_store=store)
    assert len(archive_reloaded.cells) == 1
    assert archive_reloaded.qd_score() == pytest.approx(0.75)

    matrix = archive_reloaded.get_matrix_data()
    assert len(matrix) == 1
    assert matrix[0]["vuln_class"] == "xss"


def test_hall_of_fame_sqlite_persistence(temp_db):
    store = PersistenceStore(db_path=temp_db)
    hof = HallOfFame(persistence_store=store)

    g = Genome(vuln_class=VulnClass.COMMAND_INJECTION, rendered_payload="127.0.0.1; whoami")
    hof.archive_red_elite(g, generation=12, confirmed_by="lead_analyst")
    hof.archive_blue_snapshot("/app/models/model_v2.joblib", generation=12)

    # Reload in fresh instance
    hof_reloaded = HallOfFame(persistence_store=store)
    assert len(hof_reloaded.entries) == 2
    assert len(hof_reloaded.get_red_elites()) == 1
    assert len(hof_reloaded.get_blue_snapshots()) == 1
    assert hof_reloaded.get_red_elites()[0].rendered_payload == "127.0.0.1; whoami"
