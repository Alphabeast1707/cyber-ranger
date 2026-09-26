import json
from pathlib import Path
import sqlite3
from typing import Any, Optional

from cyberranger.genome import Genome
from cyberranger.operators.bandit import OperatorBandit
from cyberranger.population import Population

DEFAULT_DB_PATH = Path("checkpoints.db")


class PersistenceStore:
    """SQLite checkpoint store for red population and bandit state (§2, §11)."""

    def __init__(self, db_path: Optional[Path | str] = None):
        self.db_path = Path(db_path) if db_path else DEFAULT_DB_PATH
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS checkpoints (
                    generation INTEGER PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    bandit_state TEXT NOT NULL,
                    population_count INTEGER NOT NULL,
                    population_data TEXT NOT NULL
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS genomes (
                    id TEXT PRIMARY KEY,
                    generation INTEGER,
                    operator_used TEXT,
                    vuln_class TEXT,
                    injection_point TEXT,
                    evasion_technique TEXT,
                    rendered_payload TEXT,
                    metadata TEXT
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS triage_items (
                    id TEXT PRIMARY KEY,
                    genome_id TEXT,
                    status TEXT NOT NULL,
                    archive_cell_status TEXT,
                    fitness REAL,
                    reviewer_note TEXT,
                    reviewed_at TEXT,
                    reviewer_id TEXT,
                    created_at TEXT NOT NULL,
                    data_json TEXT NOT NULL
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS archive_cells (
                    cell_key TEXT PRIMARY KEY,
                    genome_id TEXT,
                    fitness REAL,
                    inserted_at TEXT NOT NULL,
                    data_json TEXT NOT NULL
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS hall_of_fame (
                    id TEXT PRIMARY KEY,
                    entry_type TEXT NOT NULL,
                    genome_id TEXT,
                    blue_model_path TEXT,
                    retired_at_generation INTEGER,
                    confirmed_by TEXT,
                    created_at TEXT NOT NULL,
                    data_json TEXT NOT NULL
                )
            """)
            conn.commit()

    def checkpoint(
        self,
        population: Population,
        bandit: OperatorBandit,
        generation: int,
    ):
        """Save a snapshot of population and bandit state to SQLite (§11)."""
        import datetime

        bandit_state = {
            "arms": bandit.arms,
            "counts": bandit.counts,
            "total_reward": bandit.total_reward,
            "t": bandit.t,
        }

        pop_data = [g.to_dict() for g in population.individuals]

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO checkpoints
                (generation, timestamp, bandit_state, population_count, population_data)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    int(generation),
                    datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    json.dumps(bandit_state),
                    len(pop_data),
                    json.dumps(pop_data),
                ),
            )

            # Record individual genomes
            for g in population.individuals:
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO genomes
                    (id, generation, operator_used, vuln_class, injection_point, evasion_technique, rendered_payload, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        g.id,
                        g.generation,
                        g.operator_used,
                        g.vuln_class.value,
                        g.injection_point,
                        g.evasion_technique.value,
                        g.rendered_payload,
                        json.dumps(g.metadata),
                    ),
                )
            conn.commit()

    def load_latest_checkpoint(
        self,
        population: Optional[Population] = None,
        bandit: Optional[OperatorBandit] = None,
    ) -> Optional[int]:
        """Load latest checkpoint from database and restore population and bandit state."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT generation, bandit_state, population_data
                FROM checkpoints
                ORDER BY generation DESC
                LIMIT 1
            """)
            row = cursor.fetchone()
            if not row:
                return None

            gen, bandit_json, pop_json = row

            if bandit:
                b_state = json.loads(bandit_json)
                bandit.arms = b_state["arms"]
                bandit.counts = b_state["counts"]
                bandit.total_reward = b_state["total_reward"]
                bandit.t = b_state["t"]

            if population:
                p_list = json.loads(pop_json)
                population.gen = gen
                population.individuals = [Genome.from_dict(d) for d in p_list]

            return gen

    # --- Triage Persistence ---

    def save_triage_item(self, item: Any):
        """Save or update a TriageItem in the database."""
        import datetime
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO triage_items
                (id, genome_id, status, archive_cell_status, fitness, reviewer_note, reviewed_at, reviewer_id, created_at, data_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, COALESCE((SELECT created_at FROM triage_items WHERE id = ?), ?), ?)
                """,
                (
                    item.id,
                    item.genome.id,
                    item.status,
                    item.archive_cell_status,
                    float(item.fitness),
                    item.reviewer_note,
                    item.reviewed_at,
                    getattr(item, "reviewer_id", "security_analyst"),
                    item.id,
                    now_iso,
                    json.dumps(item.to_dict()),
                ),
            )
            conn.commit()

    def get_triage_item(self, item_id: str) -> Optional[Any]:
        """Retrieve a single TriageItem by id."""
        from cyberranger.triage import TriageItem
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT data_json FROM triage_items WHERE id = ?", (item_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return TriageItem.from_dict(json.loads(row[0]))

    def list_triage_items(self, status: Optional[str] = None) -> list[Any]:
        """List triage items, optionally filtered by status."""
        from cyberranger.triage import TriageItem
        items = []
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            if status:
                cursor.execute(
                    "SELECT data_json FROM triage_items WHERE status = ? ORDER BY created_at DESC",
                    (status,),
                )
            else:
                cursor.execute("SELECT data_json FROM triage_items ORDER BY created_at DESC")
            for row in cursor.fetchall():
                try:
                    items.append(TriageItem.from_dict(json.loads(row[0])))
                except Exception:
                    continue
        return items

    def update_triage_item_status(
        self,
        item_id: str,
        new_status: str,
        reviewer_note: Optional[str] = None,
        reviewer_id: str = "security_analyst",
    ) -> Optional[Any]:
        """Update triage item status and persist."""
        import datetime
        item = self.get_triage_item(item_id)
        if not item:
            return None
        item.status = new_status
        item.reviewer_note = reviewer_note
        item.reviewed_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        setattr(item, "reviewer_id", reviewer_id)
        self.save_triage_item(item)
        return item

    # --- MAP-Elites Archive Persistence ---

    def save_archive_cell(self, cell_key_tuple: tuple, genome: Genome, result: Any, fitness: float):
        """Save or update an archive cell in SQLite."""
        import datetime
        from cyberranger.genome import BehaviorDescriptor
        cleaned_key = [
            getattr(k, "value", str(k).split(".", 1)[-1].lower() if "." in str(k) else str(k))
            for k in cell_key_tuple
        ]
        key_str = json.dumps(cleaned_key)
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        data_json = json.dumps({
            "key": cleaned_key,
            "genome": genome.to_dict(),
            "trial_result": result.to_dict(),
            "fitness": float(fitness),
        })
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO archive_cells
                (cell_key, genome_id, fitness, inserted_at, data_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (key_str, genome.id, float(fitness), now_iso, data_json),
            )
            conn.commit()

    def load_archive_cells(self) -> dict[tuple, tuple[Genome, Any, float]]:
        """Load all archive cells from database."""
        from cyberranger.genome import TrialResult, VulnClass, EvasionTechnique
        cells = {}
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT cell_key, data_json FROM archive_cells")
            for key_str, data_str in cursor.fetchall():
                try:
                    data = json.loads(data_str)
                    raw_key = json.loads(key_str)
                    clean_tuple = []
                    for idx, item in enumerate(raw_key):
                        val = getattr(item, "value", str(item).split(".", 1)[-1].lower() if "." in str(item) else str(item))
                        if idx == 0:
                            try:
                                val = VulnClass(val)
                            except Exception:
                                pass
                        elif idx == 2:
                            try:
                                val = EvasionTechnique(val)
                            except Exception:
                                pass
                        clean_tuple.append(val)

                    genome = Genome.from_dict(data["genome"])
                    trial_result = TrialResult.from_dict(data["trial_result"])
                    fitness = float(data["fitness"])
                    cells[tuple(clean_tuple)] = (genome, trial_result, fitness)
                except Exception:
                    continue
        return cells


    # --- Hall of Fame Persistence ---

    def save_hall_of_fame_entry(self, entry: Any):
        """Save a HallOfFameEntry in SQLite."""
        import datetime
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        data_json = json.dumps({
            "id": entry.id,
            "entry_type": entry.entry_type,
            "genome": entry.genome.to_dict() if entry.genome else None,
            "blue_model_path": entry.blue_model_path,
            "retired_at_generation": entry.retired_at_generation,
            "confirmed_by": entry.confirmed_by,
        })
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO hall_of_fame
                (id, entry_type, genome_id, blue_model_path, retired_at_generation, confirmed_by, created_at, data_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry.id,
                    entry.entry_type,
                    entry.genome.id if entry.genome else None,
                    entry.blue_model_path,
                    entry.retired_at_generation,
                    entry.confirmed_by,
                    now_iso,
                    data_json,
                ),
            )
            conn.commit()

    def load_hall_of_fame_entries(self) -> list[Any]:
        """Load all HallOfFame entries from SQLite."""
        from cyberranger.hall_of_fame import HallOfFameEntry
        entries = []
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT data_json FROM hall_of_fame ORDER BY created_at ASC")
            for row in cursor.fetchall():
                try:
                    d = json.loads(row[0])
                    genome = Genome.from_dict(d["genome"]) if d.get("genome") else None
                    entry = HallOfFameEntry(
                        id=d["id"],
                        entry_type=d["entry_type"],
                        genome=genome,
                        blue_model_path=d.get("blue_model_path"),
                        retired_at_generation=int(d.get("retired_at_generation", 0)),
                        confirmed_by=d.get("confirmed_by", "security_analyst"),
                    )
                    entries.append(entry)
                except Exception:
                    continue
        return entries

