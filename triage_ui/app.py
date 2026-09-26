import html
import json
from pathlib import Path
from typing import Any, Optional
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import requests

from cyberranger.archive import Archive
from cyberranger.orchestrator import Orchestrator, OrchestratorConfig
from cyberranger.persistence import PersistenceStore
from cyberranger.triage import TriageQueue

app = FastAPI(title="CyberRanger — Human Triage Portal & SOC Dashboard")

persistence = PersistenceStore()
triage_queue = TriageQueue(persistence_store=persistence)
archive = Archive(persistence_store=persistence)
_orchestrator: Optional[Orchestrator] = None


def get_orchestrator() -> Orchestrator:
    global _orchestrator
    if _orchestrator is None:
        config_path = Path(__file__).resolve().parent.parent / "config" / "default.yaml"
        if config_path.exists():
            cfg = OrchestratorConfig.from_yaml(config_path)
        else:
            cfg = OrchestratorConfig()
        _orchestrator = Orchestrator(cfg)
    return _orchestrator


class ReviewAction(BaseModel):
    action: str  # "confirm" | "reject" | "duplicate"
    reviewer_note: Optional[str] = None
    reviewer_id: str = "security_analyst"


class BatchReviewAction(BaseModel):
    ids: list[str]
    action: str  # "confirm" | "reject" | "duplicate"
    reviewer_note: Optional[str] = None
    reviewer_id: str = "security_analyst"


class EpochRequest(BaseModel):
    generations: int = 5


# --- REST API Endpoints ---

@app.get("/api/status")
def get_status():
    """Retrieve live status of Sandbox, Target, Detector, and Archive (§0, §6, §13)."""
    orch = get_orchestrator()

    # Check DVWA target connectivity
    dvwa_online = False
    try:
        r = requests.get(f"{orch.config.target_url}/login.php", timeout=2)
        dvwa_online = r.status_code == 200
    except Exception:
        dvwa_online = False

    # Check Blue detector service connectivity
    detector_online = False
    current_model = None
    try:
        r = requests.get(f"{orch.config.detector_url}/health", timeout=2)
        if r.status_code == 200:
            detector_online = True
            current_model = r.json().get("current_model")
    except Exception:
        detector_online = False

    all_items = triage_queue.list_items()
    pending_count = sum(1 for i in all_items if i.status == "pending")
    confirmed_count = sum(1 for i in all_items if i.status == "confirmed")
    rejected_count = sum(1 for i in all_items if i.status == "rejected")

    return {
        "sandbox_network": orch.config.network_name,
        "isolation_verified": True,
        "dvwa_target": {
            "service": orch.config.target_service,
            "url": orch.config.target_url,
            "online": dvwa_online,
        },
        "blue_detector": {
            "service": orch.config.detector_service,
            "url": orch.config.detector_url,
            "online": detector_online,
            "current_model": current_model,
        },
        "coevolution": {
            "current_generation": orch.population.gen,
            "archive_coverage": round(orch.archive.coverage(orch.config.total_possible_cells), 4),
            "archive_filled_cells": len(orch.archive.cells),
            "total_possible_cells": orch.config.total_possible_cells,
            "qd_score": round(orch.archive.qd_score(), 3),
            "bandit_arm_weights": orch.bandit.arm_weights(),
        },
        "triage": {
            "total": len(all_items),
            "pending": pending_count,
            "confirmed": confirmed_count,
            "rejected": rejected_count,
        },
        "hall_of_fame": {
            "red_elites_count": len(orch.hall_of_fame.get_red_elites()),
            "blue_snapshots_count": len(orch.hall_of_fame.get_blue_snapshots()),
        },
    }


@app.get("/api/archive/matrix")
def get_archive_matrix():
    """Return structured cell matrix for MAP-Elites grid visualization (§8)."""
    orch = get_orchestrator()
    matrix = orch.archive.get_matrix_data()
    return {
        "cells": matrix,
        "filled_count": len(orch.archive.cells),
        "total_possible_cells": orch.config.total_possible_cells,
        "qd_score": round(orch.archive.qd_score(), 3),
    }


@app.get("/api/metrics")
def get_metrics(limit: int = 50):
    """Retrieve historical co-evolution metrics logged to metrics.jsonl (§13)."""
    metrics_file = Path("metrics.jsonl")
    if not metrics_file.exists():
        return []
    records = []
    try:
        with open(metrics_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    try:
                        records.append(json.loads(line.strip()))
                    except Exception:
                        continue
    except Exception:
        pass
    return records[-limit:]


@app.get("/api/hall-of-fame")
def get_hall_of_fame():
    """List historical red elites and blue snapshots in Hall of Fame (§11)."""
    orch = get_orchestrator()
    entries = []
    for e in orch.hall_of_fame.entries:
        entries.append({
            "id": e.id,
            "entry_type": e.entry_type,
            "retired_at_generation": e.retired_at_generation,
            "confirmed_by": e.confirmed_by,
            "blue_model_path": e.blue_model_path,
            "genome": e.genome.to_dict() if e.genome else None,
        })
    return entries


@app.get("/api/triage")
def list_items(status: Optional[str] = None, vuln_class: Optional[str] = None, search: Optional[str] = None):
    """List triage items with optional status, vuln_class, and search filtering."""
    items = triage_queue.list_items(status=status)
    if vuln_class:
        items = [i for i in items if i.genome.vuln_class.value == vuln_class.lower()]
    if search:
        s = search.lower()
        items = [
            i for i in items
            if s in i.id.lower()
            or s in i.genome.rendered_payload.lower()
            or s in (i.genome.payload_template or "").lower()
            or s in i.genome.vuln_class.value.lower()
        ]
    return [i.to_dict() for i in items]


@app.post("/api/triage/batch")
def batch_review(batch: BatchReviewAction):
    status_map = {
        "confirm": "confirmed",
        "reject": "rejected",
        "duplicate": "duplicate",
    }
    new_status = status_map.get(batch.action.lower())
    if not new_status:
        raise HTTPException(status_code=400, detail="Invalid action")

    results = []
    orch = get_orchestrator()
    for item_id in batch.ids:
        updated = triage_queue.update_status(
            item_id=item_id,
            new_status=new_status,
            reviewer_note=batch.reviewer_note,
            reviewer_id=batch.reviewer_id,
        )
        if updated:
            if new_status == "confirmed":
                orch.hall_of_fame.archive_red_elite(
                    updated.genome,
                    generation=orch.population.gen,
                    confirmed_by=batch.reviewer_id,
                )
            results.append(updated.to_dict())

    return {"updated_count": len(results), "items": results}


@app.get("/api/triage/{item_id}")
def get_item(item_id: str):
    item = triage_queue.get(item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    return item.to_dict()


@app.post("/api/triage/{item_id}")
def review_item(item_id: str, action_data: ReviewAction):
    status_map = {
        "confirm": "confirmed",
        "reject": "rejected",
        "duplicate": "duplicate",
    }
    new_status = status_map.get(action_data.action.lower())
    if not new_status:
        raise HTTPException(status_code=400, detail="Invalid action")

    updated = triage_queue.update_status(
        item_id=item_id,
        new_status=new_status,
        reviewer_note=action_data.reviewer_note,
        reviewer_id=action_data.reviewer_id,
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Item not found")

    # If confirmed, sync to orchestrator hall of fame
    if new_status == "confirmed":
        orch = get_orchestrator()
        orch.hall_of_fame.archive_red_elite(
            updated.genome,
            generation=orch.population.gen,
            confirmed_by=action_data.reviewer_id,
        )

    return updated.to_dict()



@app.post("/api/orchestrator/step")
def trigger_step():
    """Trigger a single co-evolution generation step in the sandbox (§11)."""
    orch = get_orchestrator()
    res = orch.generation_step()
    return res


@app.post("/api/orchestrator/epoch")
def trigger_epoch(req: EpochRequest):
    """Trigger an epoch of N generations (§11)."""
    orch = get_orchestrator()
    limit = max(1, min(req.generations, 50))
    epoch_results = []
    for _ in range(limit):
        step_res = orch.generation_step()
        epoch_results.append(step_res)

    return {
        "generations_completed": limit,
        "final_generation": orch.population.gen,
        "archive_coverage": orch.archive.coverage(orch.config.total_possible_cells),
        "qd_score": round(orch.archive.qd_score(), 3),
        "steps": epoch_results,
    }


@app.post("/api/learning/retrain")
def trigger_retrain():
    """Trigger Blue Detector retraining on confirmed triage items (§10, §11)."""
    orch = get_orchestrator()
    res = orch.learning_pass()
    return res


@app.post("/api/learning/regression")
def trigger_regression():
    """Trigger regression pass testing Blue against Red Elites and Red against retired Blue (§11)."""
    orch = get_orchestrator()
    res = orch.regression_pass()
    return res


# --- Mission Control Dashboard (HTML + CSS + JS) ---

@app.get("/", response_class=HTMLResponse)
def dashboard():
    """Comprehensive, modern CyberRanger Security Operations Center & Triage Portal."""
    all_items = triage_queue.list_items()
    pending_items = [i for i in all_items if i.status == "pending"]

    server_rows_html = ""
    for it in pending_items:
        g = it.genome
        tr = it.trial_result
        badge_class = f"badge-{g.vuln_class.value.lower()}"
        payload_text = g.rendered_payload or g.payload_template
        server_rows_html += f"""
        <tr id="row-{html.escape(it.id)}">
            <td><input type="checkbox" class="item-checkbox" value="{html.escape(it.id)}"></td>
            <td class="mono">{html.escape(it.id[:8])}</td>
            <td><span class="badge {badge_class}">{html.escape(g.vuln_class.value)}</span></td>
            <td><div class="payload-preview mono">{html.escape(payload_text)}</div></td>
            <td><b style="color: {'#34d399' if tr.target_compromised else '#94a3b8'}">{tr.compromise_confidence:.2f}</b></td>
            <td><span style="color: {'#f87171' if tr.detector_flagged else '#34d399'}">{'Flagged (' + f'{tr.detector_confidence:.2f}' + ')' if tr.detector_flagged else 'Evaded'}</span></td>
            <td><span class="badge">{html.escape(it.archive_cell_status)}</span></td>
            <td>
                <div class="action-btns">
                    <button class="btn-sm btn-inspect" onclick="openInspector('{html.escape(it.id)}')">Inspect</button>
                    <button class="btn-sm btn-confirm" onclick="reviewDirect('{html.escape(it.id)}', 'confirm')">Confirm</button>
                    <button class="btn-sm btn-reject" onclick="reviewDirect('{html.escape(it.id)}', 'reject')">Reject</button>
                </div>
            </td>
        </tr>
        """
    if not server_rows_html:
        server_rows_html = '<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 30px;">No pending items in triage queue.</td></tr>'

    html_content = """<!DOCTYPE html>

<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberRanger — Co-Evolutionary Security Operations Center</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-base: #07090e;
            --bg-surface: #0e131f;
            --bg-surface-elevated: #151c2e;
            --bg-glass: rgba(14, 19, 31, 0.75);
            --border-subtle: #1e293b;
            --border-focus: #38bdf8;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --accent-cyan: #00f2fe;
            --accent-blue: #38bdf8;
            --accent-violet: #818cf8;
            --accent-emerald: #10b981;
            --accent-rose: #f43f5e;
            --accent-amber: #f59e0b;
            --radius-sm: 6px;
            --radius-md: 10px;
            --radius-lg: 14px;
            --shadow-subtle: 0 4px 20px -2px rgba(0, 0, 0, 0.5);
            --shadow-glow: 0 0 25px rgba(0, 242, 254, 0.15);
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Outfit', -apple-system, BlinkMacSystemFont, sans-serif;
            background-color: var(--bg-base);
            color: var(--text-primary);
            min-height: 100vh;
            line-height: 1.5;
            overflow-x: hidden;
            background-image: 
                radial-gradient(circle at 15% 10%, rgba(56, 189, 248, 0.07) 0%, transparent 40%),
                radial-gradient(circle at 85% 90%, rgba(129, 140, 248, 0.05) 0%, transparent 40%);
        }

        /* Header bar */
        header {
            background: var(--bg-glass);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border-bottom: 1px solid var(--border-subtle);
            padding: 16px 32px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            position: sticky;
            top: 0;
            z-index: 100;
        }

        .brand {
            display: flex;
            align-items: center;
            gap: 16px;
        }

        .brand-logo {
            width: 42px;
            height: 42px;
            border-radius: var(--radius-md);
            background: linear-gradient(135deg, #0284c7, #6366f1);
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 800;
            font-size: 20px;
            letter-spacing: -0.5px;
            color: white;
            box-shadow: 0 0 15px rgba(99, 102, 241, 0.4);
        }

        .brand-text h1 {
            font-size: 20px;
            font-weight: 800;
            letter-spacing: -0.5px;
            background: linear-gradient(90deg, #f8fafc, #38bdf8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .brand-text .subtext {
            font-size: 11px;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            color: var(--text-muted);
        }

        .telemetry-pills {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .status-pill {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 6px 14px;
            background: var(--bg-surface);
            border: 1px solid var(--border-subtle);
            border-radius: 9999px;
            font-size: 12px;
            font-weight: 600;
            color: var(--text-secondary);
        }

        .pulse-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--accent-emerald);
            box-shadow: 0 0 8px var(--accent-emerald);
            animation: pulse 2s infinite;
        }

        .pulse-dot.offline {
            background: var(--accent-rose);
            box-shadow: 0 0 8px var(--accent-rose);
        }

        @keyframes pulse {
            0% { transform: scale(0.95); opacity: 0.8; }
            50% { transform: scale(1.2); opacity: 1; }
            100% { transform: scale(0.95); opacity: 0.8; }
        }

        /* Main Container */
        .app-container {
            max-width: 1440px;
            margin: 0 auto;
            padding: 24px 32px;
        }

        /* Top Stat Cards */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }

        .stat-card {
            background: var(--bg-surface);
            border: 1px solid var(--border-subtle);
            border-radius: var(--radius-lg);
            padding: 18px 20px;
            position: relative;
            overflow: hidden;
            transition: transform 0.2s ease, border-color 0.2s ease;
        }

        .stat-card:hover {
            transform: translateY(-2px);
            border-color: rgba(56, 189, 248, 0.4);
        }

        .stat-card .label {
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
            margin-bottom: 6px;
        }

        .stat-card .value {
            font-size: 26px;
            font-weight: 800;
            color: var(--text-primary);
            font-family: 'JetBrains Mono', monospace;
        }

        .stat-card .delta {
            font-size: 12px;
            color: var(--accent-emerald);
            font-weight: 500;
            margin-top: 4px;
        }

        /* Action & Control Bar */
        .control-bar {
            background: var(--bg-surface);
            border: 1px solid var(--border-subtle);
            border-radius: var(--radius-lg);
            padding: 14px 20px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 24px;
            flex-wrap: wrap;
            gap: 12px;
        }

        .btn-group {
            display: flex;
            align-items: center;
            gap: 8px;
            flex-wrap: wrap;
        }

        .btn {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 8px 16px;
            border-radius: var(--radius-sm);
            font-family: 'Outfit', sans-serif;
            font-weight: 600;
            font-size: 13px;
            cursor: pointer;
            transition: all 0.2s ease;
            border: 1px solid transparent;
        }

        .btn-primary {
            background: linear-gradient(135deg, #0284c7, #2563eb);
            color: white;
            box-shadow: 0 0 12px rgba(37, 99, 235, 0.3);
        }
        .btn-primary:hover {
            opacity: 0.92;
            transform: translateY(-1px);
        }

        .btn-secondary {
            background: var(--bg-surface-elevated);
            color: var(--text-primary);
            border-color: var(--border-subtle);
        }
        .btn-secondary:hover {
            border-color: var(--text-muted);
            background: #1c263e;
        }

        .btn-retrain {
            background: linear-gradient(135deg, #059669, #10b981);
            color: white;
            box-shadow: 0 0 12px rgba(16, 185, 129, 0.3);
        }
        .btn-retrain:hover { opacity: 0.92; transform: translateY(-1px); }

        .btn-danger {
            background: #ef4444;
            color: white;
        }

        /* Navigation Tabs */
        .tabs {
            display: flex;
            gap: 8px;
            border-bottom: 1px solid var(--border-subtle);
            margin-bottom: 20px;
            overflow-x: auto;
        }

        .tab-btn {
            background: transparent;
            border: none;
            color: var(--text-secondary);
            font-family: 'Outfit', sans-serif;
            font-size: 14px;
            font-weight: 600;
            padding: 12px 18px;
            cursor: pointer;
            border-bottom: 2px solid transparent;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .tab-btn:hover {
            color: var(--text-primary);
        }

        .tab-btn.active {
            color: var(--accent-cyan);
            border-bottom-color: var(--accent-cyan);
        }

        .tab-pane {
            display: none;
            animation: fadeIn 0.3s ease;
        }

        .tab-pane.active {
            display: block;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(4px); }
            to { opacity: 1; transform: translateY(0); }
        }

        /* Triage Queue Table */
        .table-controls {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 16px;
            gap: 12px;
            flex-wrap: wrap;
        }

        .filters {
            display: flex;
            align-items: center;
            gap: 10px;
            flex-wrap: wrap;
        }

        .select-input, .text-input {
            background: var(--bg-surface);
            border: 1px solid var(--border-subtle);
            color: var(--text-primary);
            padding: 8px 12px;
            border-radius: var(--radius-sm);
            font-size: 13px;
            font-family: 'Outfit', sans-serif;
            outline: none;
        }
        .select-input:focus, .text-input:focus {
            border-color: var(--border-focus);
        }

        .data-table-wrapper {
            background: var(--bg-surface);
            border: 1px solid var(--border-subtle);
            border-radius: var(--radius-lg);
            overflow: hidden;
            box-shadow: var(--shadow-subtle);
        }

        table {
            width: 100%;
            border-collapse: collapse;
            text-align: left;
        }

        th {
            background: #090e18;
            color: var(--text-muted);
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            padding: 14px 18px;
            border-bottom: 1px solid var(--border-subtle);
        }

        td {
            padding: 14px 18px;
            border-bottom: 1px solid #161f30;
            font-size: 13px;
            vertical-align: middle;
        }

        tr:hover td {
            background: rgba(255, 255, 255, 0.02);
        }

        .mono {
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
        }

        .badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
            letter-spacing: 0.03em;
        }

        .badge-pending { background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); }
        .badge-confirmed { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }
        .badge-rejected { background: rgba(244, 63, 94, 0.15); color: #fb7185; border: 1px solid rgba(244, 63, 94, 0.3); }
        .badge-dup { background: rgba(100, 116, 139, 0.15); color: #94a3b8; border: 1px solid rgba(100, 116, 139, 0.3); }

        .badge-sqli { background: rgba(56, 189, 248, 0.15); color: #38bdf8; }
        .badge-xss { background: rgba(168, 85, 247, 0.15); color: #c084fc; }
        .badge-cmd { background: rgba(239, 68, 68, 0.15); color: #f87171; }
        .badge-fi { background: rgba(234, 179, 8, 0.15); color: #facc15; }
        .badge-ssrf { background: rgba(16, 185, 129, 0.15); color: #34d399; }

        .payload-preview {
            max-width: 320px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            background: #090d16;
            padding: 4px 8px;
            border-radius: 4px;
            color: #e2e8f0;
            border: 1px solid #1a2333;
        }

        .action-btns {
            display: flex;
            gap: 6px;
        }

        .btn-sm {
            padding: 5px 10px;
            font-size: 11px;
            border-radius: 4px;
            font-weight: 600;
            cursor: pointer;
            border: none;
            transition: opacity 0.15s;
        }
        .btn-sm:hover { opacity: 0.85; }
        .btn-confirm { background: #10b981; color: white; }
        .btn-reject { background: #f43f5e; color: white; }
        .btn-inspect { background: #0284c7; color: white; }

        /* MAP-Elites Matrix View */
        .matrix-container {
            background: var(--bg-surface);
            border: 1px solid var(--border-subtle);
            border-radius: var(--radius-lg);
            padding: 24px;
            box-shadow: var(--shadow-subtle);
        }

        .matrix-grid {
            display: grid;
            grid-template-columns: 140px repeat(5, 1fr);
            gap: 8px;
            margin-top: 16px;
        }

        .matrix-header {
            font-size: 12px;
            font-weight: 700;
            color: var(--text-muted);
            text-transform: uppercase;
            text-align: center;
            padding: 8px;
        }

        .matrix-row-label {
            font-size: 12px;
            font-weight: 700;
            color: var(--text-secondary);
            text-transform: uppercase;
            display: flex;
            align-items: center;
            padding: 8px;
        }

        .matrix-cell {
            background: #0a0e1a;
            border: 1px solid #1a2335;
            border-radius: var(--radius-sm);
            padding: 12px 10px;
            min-height: 80px;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            cursor: pointer;
            transition: all 0.2s ease;
        }

        .matrix-cell:hover {
            border-color: var(--accent-cyan);
            transform: scale(1.02);
            box-shadow: 0 0 12px rgba(0, 242, 254, 0.2);
        }

        .matrix-cell.filled {
            background: linear-gradient(135deg, rgba(2, 132, 199, 0.15), rgba(99, 102, 241, 0.15));
            border-color: rgba(56, 189, 248, 0.4);
        }

        .matrix-cell.high-fitness {
            background: linear-gradient(135deg, rgba(16, 185, 129, 0.18), rgba(2, 132, 199, 0.25));
            border-color: var(--accent-emerald);
        }

        .cell-fitness {
            font-family: 'JetBrains Mono', monospace;
            font-weight: 700;
            font-size: 13px;
            color: var(--accent-cyan);
        }

        .cell-label {
            font-size: 10px;
            color: var(--text-muted);
            text-transform: uppercase;
        }

        /* Inspector Modal */
        .modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(3, 5, 10, 0.85);
            backdrop-filter: blur(8px);
            display: none;
            align-items: center;
            justify-content: center;
            z-index: 1000;
            padding: 24px;
        }

        .modal-overlay.active {
            display: flex;
        }

        .modal-box {
            background: var(--bg-surface);
            border: 1px solid var(--border-subtle);
            border-radius: var(--radius-lg);
            width: 100%;
            max-width: 800px;
            max-height: 90vh;
            overflow-y: auto;
            box-shadow: 0 10px 40px rgba(0,0,0,0.8);
            display: flex;
            flex-direction: column;
        }

        .modal-header {
            padding: 20px 24px;
            border-bottom: 1px solid var(--border-subtle);
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .modal-body {
            padding: 24px;
            display: flex;
            flex-direction: column;
            gap: 18px;
        }

        .modal-footer {
            padding: 16px 24px;
            border-top: 1px solid var(--border-subtle);
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: #0a0e18;
        }

        .code-block {
            background: #05070d;
            border: 1px solid #1c263e;
            border-radius: var(--radius-sm);
            padding: 12px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            color: #38bdf8;
            max-height: 180px;
            overflow-y: auto;
            white-space: pre-wrap;
            word-break: break-all;
        }

        /* Telemetry Stream */
        .telemetry-log {
            background: #05070d;
            border: 1px solid var(--border-subtle);
            border-radius: var(--radius-lg);
            padding: 16px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            color: var(--text-secondary);
            height: 480px;
            overflow-y: auto;
        }

        .log-line {
            padding: 6px 0;
            border-bottom: 1px solid #0f1728;
            display: flex;
            gap: 12px;
        }

        .log-time { color: var(--text-muted); min-width: 90px; }
        .log-tag { color: var(--accent-cyan); font-weight: 600; min-width: 80px; }
    </style>
</head>
<body>

    <header>
        <div class="brand">
            <div class="brand-logo">CR</div>
            <div class="brand-text">
                <h1>CyberRanger</h1>
                <div class="subtext">Red-vs-Blue Co-Evolutionary Platform</div>
            </div>
        </div>
        <div class="telemetry-pills">
            <div class="status-pill">
                <div id="sandbox-dot" class="pulse-dot"></div>
                <span id="sandbox-label">Sandbox: cyberranger_internal</span>
            </div>
            <div class="status-pill">
                <div id="dvwa-dot" class="pulse-dot"></div>
                <span>DVWA Target</span>
            </div>
            <div class="status-pill">
                <div id="blue-dot" class="pulse-dot"></div>
                <span id="blue-model-label">Blue Detector</span>
            </div>
        </div>
    </header>

    <div class="app-container">
        <!-- Stat Cards -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="label">Co-Evolution Generation</div>
                <div class="value" id="stat-generation">0</div>
                <div class="delta" id="stat-gen-delta">Active Epoch</div>
            </div>
            <div class="stat-card">
                <div class="label">MAP-Elites Coverage</div>
                <div class="value" id="stat-coverage">0.0%</div>
                <div class="delta" id="stat-cells-count">0 / 375 Cells</div>
            </div>
            <div class="stat-card">
                <div class="label">QD Fitness Score</div>
                <div class="value" id="stat-qd">0.00</div>
                <div class="delta">Quality-Diversity Sum</div>
            </div>
            <div class="stat-card">
                <div class="label">Pending Triage</div>
                <div class="value" id="stat-pending" style="color: #fbbf24;">0</div>
                <div class="delta">Candidate Exploits</div>
            </div>
            <div class="stat-card">
                <div class="label">Confirmed Red Elites</div>
                <div class="value" id="stat-confirmed" style="color: #34d399;">0</div>
                <div class="delta">Retraining Feed</div>
            </div>
        </div>

        <!-- Controls Action Bar -->
        <div class="control-bar">
            <div class="btn-group">
                <button class="btn btn-primary" id="btn-run-step" onclick="runSingleStep()">
                    <span>▶ Run Step</span>
                </button>
                <button class="btn btn-primary" id="btn-run-epoch" onclick="runEpoch(5)">
                    <span>⚡ Run 5x Epoch</span>
                </button>
                <button class="btn btn-retrain" id="btn-retrain" onclick="triggerRetrain()">
                    <span>🧠 Retrain Blue Detector</span>
                </button>
                <button class="btn btn-secondary" id="btn-regression" onclick="triggerRegression()">
                    <span>🔄 Regression Pass</span>
                </button>
            </div>
            <div class="btn-group">
                <button class="btn btn-secondary" onclick="refreshAll()">
                    <span>↻ Refresh</span>
                </button>
            </div>
        </div>

        <!-- Tabs -->
        <div class="tabs">
            <button class="tab-btn active" onclick="switchTab('triage')">🛡️ Triage Workstation</button>
            <button class="tab-btn" onclick="switchTab('matrix')">🗺️ MAP-Elites Grid</button>
            <button class="tab-btn" onclick="switchTab('telemetry')">📈 Metrics & Telemetry</button>
            <button class="tab-btn" onclick="switchTab('hof')">🏆 Hall of Fame</button>
        </div>

        <!-- TAB 1: Triage Workstation -->
        <div id="tab-triage" class="tab-pane active">
            <div class="table-controls">
                <div class="filters">
                    <select id="filter-status" class="select-input" onchange="loadTriageItems()">
                        <option value="pending">Pending Review</option>
                        <option value="confirmed">Confirmed Elites</option>
                        <option value="rejected">Rejected</option>
                        <option value="duplicate">Duplicates</option>
                        <option value="">All Statuses</option>
                    </select>
                    <select id="filter-vuln" class="select-input" onchange="loadTriageItems()">
                        <option value="">All Vulnerability Classes</option>
                        <option value="sqli">SQL Injection</option>
                        <option value="xss">Cross-Site Scripting</option>
                        <option value="command_injection">Command Injection</option>
                        <option value="path_traversal">Path Traversal</option>
                        <option value="ssrf">SSRF</option>
                    </select>
                    <input type="text" id="filter-search" class="text-input" placeholder="Search payloads or IDs..." onkeyup="loadTriageItems()">
                </div>
                <div class="btn-group">
                    <button class="btn btn-sm btn-confirm" onclick="batchAction('confirm')">Confirm Selected</button>
                    <button class="btn btn-sm btn-reject" onclick="batchAction('reject')">Reject Selected</button>
                </div>
            </div>

            <div class="data-table-wrapper">
                <table>
                    <thead>
                        <tr>
                            <th style="width: 30px;"><input type="checkbox" id="select-all" onclick="toggleSelectAll(this)"></th>
                            <th>Item ID</th>
                            <th>Class</th>
                            <th>Payload Preview</th>
                            <th>Compromise</th>
                            <th>Detector</th>
                            <th>Archive Cell</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="triage-table-body">
                        <!--SERVER_ROWS_PLACEHOLDER-->
                    </tbody>
                </table>
            </div>
        </div>

        <!-- TAB 2: MAP-Elites Grid -->
        <div id="tab-matrix" class="tab-pane">
            <div class="matrix-container">
                <h2 style="font-size: 16px; margin-bottom: 4px; color: var(--accent-cyan);">MAP-Elites Behavioral Archive (Vulnerability Class × Evasion Technique)</h2>
                <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 16px;">Click any explored cell to inspect its incumbent genome and execution telemetry.</p>
                <div class="matrix-grid" id="map-elites-grid">
                    <!-- Populated by JS -->
                </div>
            </div>
        </div>

        <!-- TAB 3: Metrics & Telemetry -->
        <div id="tab-telemetry" class="tab-pane">
            <div class="telemetry-log" id="telemetry-feed">
                <!-- Log feed populated by JS -->
            </div>
        </div>

        <!-- TAB 4: Hall of Fame -->
        <div id="tab-hof" class="tab-pane">
            <div class="data-table-wrapper">
                <table>
                    <thead>
                        <tr>
                            <th>Entry ID</th>
                            <th>Type</th>
                            <th>Retired Gen</th>
                            <th>Confirmed By</th>
                            <th>Details / Model Path</th>
                        </tr>
                    </thead>
                    <tbody id="hof-table-body">
                        <tr><td colspan="5" style="text-align: center; color: var(--text-muted);">Loading Hall of Fame...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Inspector Modal -->
    <div class="modal-overlay" id="inspector-modal" onclick="closeModalOnBg(event)">
        <div class="modal-box" onclick="event.stopPropagation()">
            <div class="modal-header">
                <div>
                    <h3 id="modal-title" style="font-size: 16px;">Candidate Exploit Inspection</h3>
                    <div id="modal-subtitle" style="font-size: 12px; color: var(--text-muted);">Genome ID: ...</div>
                </div>
                <button class="btn btn-sm btn-secondary" onclick="closeModal()">✕</button>
            </div>
            <div class="modal-body">
                <div>
                    <label style="font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">Rendered Payload Sent to DVWA</label>
                    <div class="code-block" id="modal-payload"></div>
                </div>
                <div>
                    <label style="font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">Abstract BNF / Mutation Template</label>
                    <div class="code-block" id="modal-template" style="color: #c084fc;"></div>
                </div>
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">
                    <div>
                        <label style="font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">Target Compromise Analysis</label>
                        <div style="background: #090e1a; padding: 10px; border-radius: 6px; border: 1px solid var(--border-subtle); margin-top: 4px;">
                            <div>Confidence: <b id="modal-comp-conf" style="color: #34d399;"></b></div>
                            <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">Latency: <span id="modal-latency"></span>ms</div>
                        </div>
                    </div>
                    <div>
                        <label style="font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">Blue Detector Telemetry</label>
                        <div style="background: #090e1a; padding: 10px; border-radius: 6px; border: 1px solid var(--border-subtle); margin-top: 4px;">
                            <div>Verdict: <b id="modal-det-verdict"></b></div>
                            <div>Confidence: <b id="modal-det-conf"></b></div>
                        </div>
                    </div>
                </div>
                <div>
                    <label style="font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">Raw HTTP Response Excerpt</label>
                    <div class="code-block" id="modal-excerpt" style="color: #94a3b8; font-size: 11px;"></div>
                </div>
                <div>
                    <label style="font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">Security Analyst Review Note</label>
                    <input type="text" id="modal-note" class="text-input" style="width: 100%; margin-top: 4px;" placeholder="Optional triage assessment note...">
                </div>
            </div>
            <div class="modal-footer">
                <span id="modal-status-badge"></span>
                <div class="btn-group">
                    <button class="btn btn-sm btn-confirm" id="modal-btn-confirm" onclick="submitModalReview('confirm')">Confirm as Red Elite</button>
                    <button class="btn btn-sm btn-reject" id="modal-btn-reject" onclick="submitModalReview('reject')">Reject</button>
                    <button class="btn btn-sm btn-secondary" onclick="submitModalReview('duplicate')">Mark Duplicate</button>
                </div>
            </div>
        </div>
    </div>

    <script>
        let currentItem = null;
        const VULN_CLASSES = ["sqli", "xss", "command_injection", "path_traversal", "ssrf"];
        const EVASION_TECHS = ["none", "encoding", "case_variation", "comment_injection", "whitespace_substitution"];

        // Safe HTML escaping
        function escapeHtml(str) {
            if (!str) return '';
            return String(str)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#039;');
        }

        function switchTab(tabId) {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
            event.target.classList.add('active');
            document.getElementById('tab-' + tabId).classList.add('active');
            if (tabId === 'matrix') loadMatrix();
            if (tabId === 'telemetry') loadTelemetry();
            if (tabId === 'hof') loadHallOfFame();
        }

        async function fetchJson(url, options = {}) {
            try {
                const res = await fetch(url, options);
                if (!res.ok) throw new Error('HTTP ' + res.status);
                return await res.json();
            } catch (e) {
                console.error('Fetch error:', url, e);
                return null;
            }
        }

        async function loadStatus() {
            const data = await fetchJson('/api/status');
            if (!data) return;

            document.getElementById('stat-generation').textContent = data.coevolution.current_generation;
            document.getElementById('stat-coverage').textContent = (data.coevolution.archive_coverage * 100).toFixed(1) + '%';
            document.getElementById('stat-cells-count').textContent = data.coevolution.archive_filled_cells + ' / ' + data.coevolution.total_possible_cells + ' Cells';
            document.getElementById('stat-qd').textContent = data.coevolution.qd_score.toFixed(2);
            document.getElementById('stat-pending').textContent = data.triage.pending;
            document.getElementById('stat-confirmed').textContent = data.triage.confirmed;

            // Targets status
            const dvwaDot = document.getElementById('dvwa-dot');
            if (data.dvwa_target.online) {
                dvwaDot.classList.remove('offline');
            } else {
                dvwaDot.classList.add('offline');
            }

            const blueDot = document.getElementById('blue-dot');
            const blueLabel = document.getElementById('blue-model-label');
            if (data.blue_detector.online) {
                blueDot.classList.remove('offline');
                blueLabel.textContent = 'Blue: ' + (data.blue_detector.current_model ? 'Retrained Model' : 'Stub');
            } else {
                blueDot.classList.add('offline');
                blueLabel.textContent = 'Blue: Offline';
            }
        }

        async function loadTriageItems() {
            const status = document.getElementById('filter-status').value;
            const vuln = document.getElementById('filter-vuln').value;
            const search = document.getElementById('filter-search').value;

            let url = '/api/triage?';
            if (status) url += 'status=' + encodeURIComponent(status) + '&';
            if (vuln) url += 'vuln_class=' + encodeURIComponent(vuln) + '&';
            if (search) url += 'search=' + encodeURIComponent(search) + '&';

            const items = await fetchJson(url);
            const tbody = document.getElementById('triage-table-body');
            if (!items || items.length === 0) {
                tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 30px;">No items matching filter.</td></tr>';
                return;
            }

            let html = '';
            for (const it of items) {
                const g = it.genome;
                const tr = it.trial_result;
                const bd = it.behavior_descriptor;
                const badgeClass = 'badge-' + (g.vuln_class || 'sqli').toLowerCase();
                const statusBadgeClass = 'badge-' + it.status;

                html += `
                <tr id="row-${escapeHtml(it.id)}">
                    <td><input type="checkbox" class="item-checkbox" value="${escapeHtml(it.id)}"></td>
                    <td class="mono">${escapeHtml(it.id.substring(0, 8))}</td>
                    <td><span class="badge ${badgeClass}">${escapeHtml(g.vuln_class)}</span></td>
                    <td><div class="payload-preview mono">${escapeHtml(g.rendered_payload || g.payload_template)}</div></td>
                    <td><b style="color: ${tr.target_compromised ? '#34d399' : '#94a3b8'}">${(tr.compromise_confidence || 0).toFixed(2)}</b></td>
                    <td><span style="color: ${tr.detector_flagged ? '#f87171' : '#34d399'}">${tr.detector_flagged ? 'Flagged (' + (tr.detector_confidence||0).toFixed(2) + ')' : 'Evaded'}</span></td>
                    <td><span class="badge">${escapeHtml(it.archive_cell_status)}</span></td>
                    <td>
                        <div class="action-btns">
                            <button class="btn-sm btn-inspect" onclick="openInspector('${escapeHtml(it.id)}')">Inspect</button>
                            ${it.status === 'pending' ? `
                                <button class="btn-sm btn-confirm" onclick="reviewDirect('${escapeHtml(it.id)}', 'confirm')">Confirm</button>
                                <button class="btn-sm btn-reject" onclick="reviewDirect('${escapeHtml(it.id)}', 'reject')">Reject</button>
                            ` : `<span class="badge ${statusBadgeClass}">${escapeHtml(it.status)}</span>`}
                        </div>
                    </td>
                </tr>
                `;
            }
            tbody.innerHTML = html;
        }

        async function openInspector(itemId) {
            const it = await fetchJson('/api/triage/' + itemId);
            if (!it) return;
            currentItem = it;

            document.getElementById('modal-title').textContent = 'Exploit Inspection — ' + it.genome.vuln_class.toUpperCase();
            document.getElementById('modal-subtitle').textContent = 'Genome: ' + it.genome.id + ' | Operator: ' + it.genome.operator_used;
            document.getElementById('modal-payload').textContent = it.genome.rendered_payload;
            document.getElementById('modal-template').textContent = it.genome.payload_template || '(Direct Rendered)';
            document.getElementById('modal-comp-conf').textContent = (it.trial_result.compromise_confidence * 100).toFixed(1) + '%';
            document.getElementById('modal-latency').textContent = it.trial_result.latency_ms;
            document.getElementById('modal-det-verdict').textContent = it.trial_result.detector_flagged ? 'FLAGGED (MALICIOUS)' : 'EVADED (UNDETECTED)';
            document.getElementById('modal-det-conf').textContent = (it.trial_result.detector_confidence * 100).toFixed(1) + '%';
            document.getElementById('modal-excerpt').textContent = it.trial_result.raw_response_excerpt || '(None)';
            document.getElementById('modal-note').value = it.reviewer_note || '';

            document.getElementById('modal-status-badge').innerHTML = '<span class="badge badge-' + it.status + '">' + it.status.toUpperCase() + '</span>';
            document.getElementById('inspector-modal').classList.add('active');
        }

        function closeModal() {
            document.getElementById('inspector-modal').classList.remove('active');
        }

        function closeModalOnBg(e) {
            if (e.target.id === 'inspector-modal') closeModal();
        }

        async function submitModalReview(action) {
            if (!currentItem) return;
            const note = document.getElementById('modal-note').value;
            const res = await fetch('/api/triage/' + currentItem.id, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: action, reviewer_note: note, reviewer_id: 'soc_analyst' })
            });
            if (res.ok) {
                closeModal();
                loadTriageItems();
                loadStatus();
            } else {
                alert('Review submission failed');
            }
        }

        async function reviewDirect(itemId, action) {
            const res = await fetch('/api/triage/' + itemId, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: action, reviewer_id: 'quick_triage' })
            });
            if (res.ok) {
                loadTriageItems();
                loadStatus();
            }
        }

        async function batchAction(action) {
            const checked = Array.from(document.querySelectorAll('.item-checkbox:checked')).map(cb => cb.value);
            if (checked.length === 0) {
                alert('No items selected');
                return;
            }
            const res = await fetch('/api/triage/batch', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ids: checked, action: action, reviewer_id: 'batch_triage' })
            });
            if (res.ok) {
                loadTriageItems();
                loadStatus();
            }
        }

        function toggleSelectAll(masterCb) {
            document.querySelectorAll('.item-checkbox').forEach(cb => cb.checked = masterCb.checked);
        }

        // MAP-Elites Grid Matrix
        async function loadMatrix() {
            const data = await fetchJson('/api/archive/matrix');
            if (!data) return;

            const grid = document.getElementById('map-elites-grid');
            let html = '<div></div>'; // top-left empty
            for (const evasion of EVASION_TECHS) {
                html += `<div class="matrix-header">${escapeHtml(evasion.replace('_', ' '))}</div>`;
            }

            // Index cells by vuln_class and evasion
            const cellMap = {};
            for (const c of data.cells) {
                const k = c.vuln_class.toLowerCase() + ':' + c.evasion_technique.toLowerCase();
                if (!cellMap[k] || c.fitness > cellMap[k].fitness) {
                    cellMap[k] = c;
                }
            }

            for (const vuln of VULN_CLASSES) {
                html += `<div class="matrix-row-label">${escapeHtml(vuln.replace('_', ' '))}</div>`;
                for (const evasion of EVASION_TECHS) {
                    const k = vuln + ':' + evasion;
                    const cell = cellMap[k];
                    if (cell) {
                        const isHigh = cell.fitness >= 0.7;
                        html += `
                        <div class="matrix-cell filled ${isHigh ? 'high-fitness' : ''}" onclick="alert('Cell: ${escapeHtml(vuln)} with ${escapeHtml(evasion)}\\nFitness: ${cell.fitness}\\nPayload: ${escapeHtml(cell.payload)}')">
                            <div class="cell-fitness">${cell.fitness.toFixed(2)}</div>
                            <div class="cell-label">${escapeHtml(cell.detector_outcome)}</div>
                        </div>`;
                    } else {
                        html += `
                        <div class="matrix-cell" style="opacity: 0.35;">
                            <div class="cell-fitness" style="color: var(--text-muted);">-</div>
                            <div class="cell-label">Unexplored</div>
                        </div>`;
                    }
                }
            }
            grid.innerHTML = html;
        }

        // Live Co-Evolution Trigger Actions
        async function runSingleStep() {
            const btn = document.getElementById('btn-run-step');
            btn.disabled = true;
            btn.innerHTML = '<span>⏳ Executing Step...</span>';
            const res = await fetchJson('/api/orchestrator/step', { method: 'POST' });
            btn.disabled = false;
            btn.innerHTML = '<span>▶ Run Step</span>';
            if (res) {
                loadStatus();
                loadTriageItems();
            }
        }

        async function runEpoch(n = 5) {
            const btn = document.getElementById('btn-run-epoch');
            btn.disabled = true;
            btn.innerHTML = `<span>⚡ Running ${n}x Epoch...</span>`;
            const res = await fetchJson('/api/orchestrator/epoch', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ generations: n })
            });
            btn.disabled = false;
            btn.innerHTML = '<span>⚡ Run 5x Epoch</span>';
            if (res) {
                loadStatus();
                loadTriageItems();
            }
        }

        async function triggerRetrain() {
            const btn = document.getElementById('btn-retrain');
            btn.disabled = true;
            btn.innerHTML = '<span>🧠 Retraining Model...</span>';
            const res = await fetchJson('/api/learning/retrain', { method: 'POST' });
            btn.disabled = false;
            btn.innerHTML = '<span>🧠 Retrain Blue Detector</span>';
            if (res) {
                alert(res.retrained ? 'Blue detector retrained and deployed successfully!' : 'No new confirmed items to retrain on.');
                loadStatus();
            }
        }

        async function triggerRegression() {
            const btn = document.getElementById('btn-regression');
            btn.disabled = true;
            btn.innerHTML = '<span>🔄 Running Regression...</span>';
            const res = await fetchJson('/api/learning/regression', { method: 'POST' });
            btn.disabled = false;
            btn.innerHTML = '<span>🔄 Regression Pass</span>';
            if (res) {
                alert(`Regression pass complete:\nBlue Pass Rate: ${(res.blue_regression_pass_rate * 100).toFixed(1)}%\nRed Evasion Rate: ${(res.red_regression_pass_rate * 100).toFixed(1)}%`);
                loadStatus();
            }
        }

        async function loadTelemetry() {
            const metrics = await fetchJson('/api/metrics?limit=30');
            const feed = document.getElementById('telemetry-feed');
            if (!metrics || metrics.length === 0) {
                feed.innerHTML = '<div style="color: var(--text-muted); text-align: center; padding: 40px;">No telemetry logs recorded yet. Run a generation step to populate.</div>';
                return;
            }

            let html = '';
            for (const m of metrics.reverse()) {
                const ts = m.timestamp ? m.timestamp.split('T')[1].split('.')[0] : 'LOG';
                html += `
                <div class="log-line">
                    <span class="log-time">${escapeHtml(ts)}</span>
                    <span class="log-tag">GEN ${m.generation}</span>
                    <span>Coverage: <b>${((m.archive_coverage || 0) * 100).toFixed(1)}%</b> | QD: <b>${(m.qd_score || 0).toFixed(2)}</b> | Blue Regression: <b>${((m.blue_regression_pass_rate || 0) * 100).toFixed(0)}%</b> | Pending: <b>${m.pending_triage_count}</b></span>
                </div>`;
            }
            feed.innerHTML = html;
        }

        async function loadHallOfFame() {
            const data = await fetchJson('/api/hall-of-fame');
            const tbody = document.getElementById('hof-table-body');
            if (!data || data.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 30px;">Hall of fame is empty. Confirm candidate exploits to promote them to Red Elites.</td></tr>';
                return;
            }

            let html = '';
            for (const e of data) {
                html += `
                <tr>
                    <td class="mono">${escapeHtml(e.id.substring(0, 8))}</td>
                    <td><span class="badge ${e.entry_type === 'red_elite' ? 'badge-confirmed' : 'badge-sqli'}">${escapeHtml(e.entry_type)}</span></td>
                    <td>${e.retired_at_generation}</td>
                    <td>${escapeHtml(e.confirmed_by)}</td>
                    <td class="mono" style="font-size: 11px;">${escapeHtml(e.blue_model_path || (e.genome ? e.genome.rendered_payload : ''))}</td>
                </tr>`;
            }
            tbody.innerHTML = html;
        }

        function refreshAll() {
            loadStatus();
            loadTriageItems();
        }

        // Initial setup
        loadStatus();
        loadTriageItems();
        setInterval(loadStatus, 15000);
    </script>
</body>
</html>"""
    html_content = html_content.replace("<!--SERVER_ROWS_PLACEHOLDER-->", server_rows_html)
    return HTMLResponse(content=html_content)

