"""JSONL logger for CyberRanger Arena.

Appends one JSON object per round to runs/session.jsonl, building a labeled
dataset that later stages (RL / supervised training) can consume directly.
"""

import json
import os
from datetime import datetime, timezone

RUNS_DIR = "runs"
SESSION_FILE = os.path.join(RUNS_DIR, "session.jsonl")


class RunLogger:
    """Appends round records to a JSONL file, one object per line."""

    def __init__(self, path=SESSION_FILE):
        self.path = path
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        # Fresh file per session so summaries match the current run.
        open(self.path, "w").close()

    def log_round(self, round_no, action, breached, blue_flagged,
                  ground_truth, correct):
        """Write a single round record and return the dict written."""
        record = {
            "round": round_no,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "red_action": action["name"],
            "category": action["category"],
            "breached": bool(breached),
            "blue_flagged": bool(blue_flagged),
            "ground_truth": ground_truth,
            "correct": bool(correct),
        }
        with open(self.path, "a") as f:
            f.write(json.dumps(record) + "\n")
        return record
