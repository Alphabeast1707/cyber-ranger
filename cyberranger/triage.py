from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Optional
import uuid

from cyberranger.genome import BehaviorDescriptor, Genome, TrialResult


@dataclass
class TriageItem:
    """Item submitted for human security analyst review (§3, §9)."""
    id: str
    genome: Genome
    trial_result: TrialResult
    behavior_descriptor: BehaviorDescriptor
    archive_cell_status: str   # "new_cell" | "replaced_incumbent"
    fitness: float
    status: str = "pending"    # "pending" | "confirmed" | "rejected" | "duplicate"
    reviewer_note: Optional[str] = None
    reviewed_at: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "genome": self.genome.to_dict(),
            "trial_result": self.trial_result.to_dict(),
            "behavior_descriptor": self.behavior_descriptor.to_dict(),
            "archive_cell_status": self.archive_cell_status,
            "fitness": self.fitness,
            "status": self.status,
            "reviewer_note": self.reviewer_note,
            "reviewed_at": self.reviewed_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TriageItem":
        return cls(
            id=data["id"],
            genome=Genome.from_dict(data["genome"]),
            trial_result=TrialResult.from_dict(data["trial_result"]),
            behavior_descriptor=BehaviorDescriptor.from_dict(data["behavior_descriptor"]),
            archive_cell_status=data["archive_cell_status"],
            fitness=float(data["fitness"]),
            status=data.get("status", "pending"),
            reviewer_note=data.get("reviewer_note"),
            reviewed_at=data.get("reviewed_at"),
        )


class TriageQueue:
    """In-memory and persistent queue of triage items awaiting analyst review (§9)."""

    def __init__(self, persistence_store: Optional[Any] = None):
        self.items: dict[str, TriageItem] = {}
        self._consumed_confirmed_ids: set[str] = set()
        self.persistence = persistence_store

        if self.persistence:
            try:
                existing = self.persistence.list_triage_items()
                for it in existing:
                    self.items[it.id] = it
            except Exception:
                pass


    def enqueue(
        self,
        genome: Genome,
        trial_result: TrialResult,
        behavior_descriptor: BehaviorDescriptor,
        archive_cell_status: str,
        fitness: float,
    ) -> TriageItem:
        """Enqueue a promising genome for human analyst triage."""
        item_id = str(uuid.uuid4())
        item = TriageItem(
            id=item_id,
            genome=genome,
            trial_result=trial_result,
            behavior_descriptor=behavior_descriptor,
            archive_cell_status=archive_cell_status,
            fitness=float(fitness),
            status="pending",
        )
        self.items[item_id] = item
        if self.persistence:
            try:
                self.persistence.save_triage_item(item)
            except Exception:
                pass
        return item

    def get(self, item_id: str) -> Optional[TriageItem]:
        if item_id in self.items:
            return self.items[item_id]
        if self.persistence:
            try:
                db_item = self.persistence.get_triage_item(item_id)
                if db_item:
                    self.items[db_item.id] = db_item
                return db_item
            except Exception:
                pass
        return None

    def list_items(self, status: Optional[str] = None) -> list[TriageItem]:
        """List items, optionally filtering by status."""
        if self.persistence:
            try:
                db_items = self.persistence.list_triage_items(status=status)
                for it in db_items:
                    self.items[it.id] = it
                return db_items
            except Exception:
                pass
        if status is None:
            return list(self.items.values())
        return [i for i in self.items.values() if i.status == status]

    def update_status(
        self,
        item_id: str,
        new_status: str,
        reviewer_note: Optional[str] = None,
        reviewer_id: str = "human_reviewer",
    ) -> Optional[TriageItem]:
        """Update an item status (confirmed, rejected, duplicate)."""
        valid_statuses = {"pending", "confirmed", "rejected", "duplicate"}
        if new_status not in valid_statuses:
            raise ValueError(f"Invalid status '{new_status}'. Allowed: {valid_statuses}")

        item = self.get(item_id)
        if not item:
            return None

        item.status = new_status
        item.reviewer_note = reviewer_note
        item.reviewed_at = datetime.now(timezone.utc).isoformat()
        if self.persistence:
            try:
                self.persistence.update_triage_item_status(
                    item_id=item_id,
                    new_status=new_status,
                    reviewer_note=reviewer_note,
                    reviewer_id=reviewer_id,
                )
            except Exception:
                pass
        return item

    def pull_confirmed_since_last_pass(self) -> list[TriageItem]:
        """Pull confirmed triage items that haven't been incorporated into blue retraining yet."""
        all_confirmed = self.list_items("confirmed")
        confirmed_items = []
        for item in all_confirmed:
            if item.id not in self._consumed_confirmed_ids:
                confirmed_items.append(item)
                self._consumed_confirmed_ids.add(item.id)
        return confirmed_items

