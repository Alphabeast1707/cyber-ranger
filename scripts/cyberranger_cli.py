#!/usr/bin/env python3
"""CyberRanger Unified CLI — Operations and Management Interface.

Usage:
    python scripts/cyberranger_cli.py status
    python scripts/cyberranger_cli.py loop --generations 10 [--resume]
    python scripts/cyberranger_cli.py retrain
    python scripts/cyberranger_cli.py regression
    python scripts/cyberranger_cli.py triage list [--status pending]
    python scripts/cyberranger_cli.py triage confirm <item_id> [--note "Note"]
    python scripts/cyberranger_cli.py triage reject <item_id>
    python scripts/cyberranger_cli.py serve [--port 8501]
"""

import argparse
import json
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from cyberranger.orchestrator import Orchestrator, OrchestratorConfig
from cyberranger.persistence import PersistenceStore
from cyberranger.triage import TriageQueue

DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "default.yaml"


def cmd_status(args):
    """Display status of sandbox, services, and co-evolution metrics."""
    cfg = OrchestratorConfig.from_yaml(args.config) if Path(args.config).exists() else OrchestratorConfig()
    store = PersistenceStore()
    triage = TriageQueue(persistence_store=store)

    import requests

    dvwa_ok = False
    try:
        r = requests.get(f"{cfg.target_url}/login.php", timeout=2)
        dvwa_ok = r.status_code == 200
    except Exception:
        pass

    blue_ok = False
    current_model = "None"
    try:
        r = requests.get(f"{cfg.detector_url}/health", timeout=2)
        if r.status_code == 200:
            blue_ok = True
            current_model = r.json().get("current_model") or "Stub"
    except Exception:
        pass

    archive_cells = store.load_archive_cells()
    hof_entries = store.load_hall_of_fame_entries()
    all_triage = triage.list_items()
    pending_triage = [i for i in all_triage if i.status == "pending"]
    confirmed_triage = [i for i in all_triage if i.status == "confirmed"]

    print("=" * 60)
    print("           CYBERRANGER SYSTEM STATUS")
    print("=" * 60)
    print(f"[*] Sandbox Network : {cfg.network_name} (internal: true)")
    print(f"[*] DVWA Target     : {cfg.target_url} [{'ONLINE' if dvwa_ok else 'OFFLINE'}]")
    print(f"[*] Blue Detector   : {cfg.detector_url} [{'ONLINE' if blue_ok else 'OFFLINE'}] (Model: {current_model})")
    print("-" * 60)
    print(f"[*] MAP-Elites Cells: {len(archive_cells)} / {cfg.total_possible_cells} ({len(archive_cells)/cfg.total_possible_cells*100:.1f}% coverage)")
    print(f"[*] QD Fitness Sum  : {sum(f for _, _, f in archive_cells.values()):.2f}")
    print(f"[*] Pending Triage  : {len(pending_triage)} items")
    print(f"[*] Confirmed Elites: {len(confirmed_triage)} items")
    print(f"[*] Hall of Fame    : {len(hof_entries)} entries ({sum(1 for e in hof_entries if e.entry_type == 'red_elite')} red, {sum(1 for e in hof_entries if e.entry_type == 'blue_snapshot')} blue)")
    print("=" * 60)


def cmd_loop(args):
    """Run co-evolution generation loop."""
    cfg = OrchestratorConfig.from_yaml(args.config) if Path(args.config).exists() else OrchestratorConfig()
    orchestrator = Orchestrator(cfg)

    if args.resume:
        resumed_gen = orchestrator.load_checkpoint()
        if resumed_gen is not None:
            print(f"[CyberRanger] Resumed from checkpoint at generation {resumed_gen}")

    print(f"[CyberRanger] Starting co-evolution generation loop for {args.generations} generations...")
    orchestrator.run(max_generations=args.generations)
    print(f"[CyberRanger] Loop finished. Current generation: {orchestrator.population.gen}")


def cmd_retrain(args):
    """Trigger Blue Detector retraining on confirmed triage items."""
    cfg = OrchestratorConfig.from_yaml(args.config) if Path(args.config).exists() else OrchestratorConfig()
    orchestrator = Orchestrator(cfg)
    res = orchestrator.learning_pass()
    if res["retrained"]:
        print(f"[CyberRanger] Retrained Blue detector on {res['confirmed_count']} confirmed exploits.")
        print(f"[CyberRanger] Saved snapshot to: {res['model_path']}")
    else:
        print("[CyberRanger] No newly confirmed triage items found to retrain on.")


def cmd_regression(args):
    """Run regression testing against historical red elites and blue snapshots."""
    cfg = OrchestratorConfig.from_yaml(args.config) if Path(args.config).exists() else OrchestratorConfig()
    orchestrator = Orchestrator(cfg)
    res = orchestrator.regression_pass()
    print(f"[CyberRanger] Regression Pass Results:")
    print(f"    Blue Detector Pass Rate : {res['blue_regression_pass_rate'] * 100:.1f}%")
    print(f"    Red Population Evasion  : {res['red_regression_pass_rate'] * 100:.1f}%")
    if res["regressed"]:
        print(f"    [WARNING] Blue detector regressed below floor of {res['regression_floor'] * 100:.1f}%!")
    else:
        print(f"    [PASS] Blue detector is stable above floor.")


def cmd_triage(args):
    """Manage human triage queue."""
    store = PersistenceStore()
    triage = TriageQueue(persistence_store=store)

    if args.triage_action == "list":
        items = triage.list_items(status=args.status)
        print(f"Found {len(items)} triage items (filter: {args.status or 'all'}):")
        print("-" * 80)
        print(f"{'ID':<10} {'CLASS':<18} {'STATUS':<10} {'COMP%':<8} {'DET%':<8} {'PAYLOAD'}")
        print("-" * 80)
        for it in items[:args.limit]:
            p = it.genome.rendered_payload or it.genome.payload_template
            p_short = (p[:30] + "...") if len(p) > 30 else p
            print(f"{it.id[:8]:<10} {it.genome.vuln_class.value:<18} {it.status:<10} {it.trial_result.compromise_confidence:<8.2f} {it.trial_result.detector_confidence:<8.2f} {p_short}")
        print("-" * 80)

    elif args.triage_action == "confirm":
        updated = triage.update_status(args.item_id, "confirmed", reviewer_note=args.note, reviewer_id=args.reviewer)
        if updated:
            print(f"[+] Confirmed item {args.item_id[:8]} as Red Elite.")
        else:
            print(f"[-] Item {args.item_id} not found.")

    elif args.triage_action == "reject":
        updated = triage.update_status(args.item_id, "rejected", reviewer_note=args.note, reviewer_id=args.reviewer)
        if updated:
            print(f"[+] Rejected item {args.item_id[:8]}.")
        else:
            print(f"[-] Item {args.item_id} not found.")


def cmd_serve(args):
    """Launch the Mission Control Web UI."""
    import uvicorn
    print(f"[CyberRanger] Launching Mission Control Dashboard at http://{args.host}:{args.port}")
    uvicorn.run("triage_ui.app:app", host=args.host, port=args.port, reload=False)


def main():
    parser = argparse.ArgumentParser(description="CyberRanger Security Research System")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH), help="Path to config file")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # status
    p_status = subparsers.add_parser("status", help="Show system status and archive telemetry")
    p_status.set_defaults(func=cmd_status)

    # loop
    p_loop = subparsers.add_parser("loop", help="Run co-evolution generation loop")
    p_loop.add_argument("--generations", type=int, default=5, help="Number of generations to execute")
    p_loop.add_argument("--resume", action="store_true", help="Resume from latest SQLite checkpoint")
    p_loop.set_defaults(func=cmd_loop)

    # retrain
    p_retrain = subparsers.add_parser("retrain", help="Retrain blue detector on confirmed triage items")
    p_retrain.set_defaults(func=cmd_retrain)

    # regression
    p_reg = subparsers.add_parser("regression", help="Run regression pass")
    p_reg.set_defaults(func=cmd_regression)

    # triage
    p_triage = subparsers.add_parser("triage", help="Manage triage queue")
    triage_sub = p_triage.add_subparsers(dest="triage_action", required=True)

    t_list = triage_sub.add_parser("list", help="List triage items")
    t_list.add_argument("--status", default="pending", help="Filter by status (pending/confirmed/rejected)")
    t_list.add_argument("--limit", type=int, default=20, help="Max items to list")

    t_conf = triage_sub.add_parser("confirm", help="Confirm a triage item as a Red Elite")
    t_conf.add_argument("item_id", help="UUID of triage item")
    t_conf.add_argument("--note", default="Confirmed via CLI", help="Reviewer note")
    t_conf.add_argument("--reviewer", default="cli_analyst", help="Reviewer ID")

    t_rej = triage_sub.add_parser("reject", help="Reject a triage item")
    t_rej.add_argument("item_id", help="UUID of triage item")
    t_rej.add_argument("--note", default="Rejected via CLI", help="Reviewer note")
    t_rej.add_argument("--reviewer", default="cli_analyst", help="Reviewer ID")

    p_triage.set_defaults(func=cmd_triage)

    # serve
    p_serve = subparsers.add_parser("serve", help="Launch web triage and monitoring dashboard")
    p_serve.add_argument("--host", default="127.0.0.1", help="Host interface (must be localhost/127.0.0.1)")
    p_serve.add_argument("--port", type=int, default=8501, help="Port to listen on")
    p_serve.set_defaults(func=cmd_serve)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
