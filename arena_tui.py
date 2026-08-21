"""CyberRanger Arena — Rich TUI dashboard (optional presenter view).

A projector-friendly live dashboard over the SAME orchestrator/agents used
by the plain console runner. It imports them without modification:

    python arena_tui.py      # rich dashboard
    python orchestrator.py   # plain fallback (unchanged)

Requires the `rich` library. If rich is missing we tell the user to use the
plain runner instead of crashing.
"""

import time

from red_agent import RedAgent
from blue_agent import BlueAgent
from environment import Environment
from logger import RunLogger
from orchestrator import DEFAULT_ROUNDS

# Seconds paused between rounds so the audience can watch each land. Tweak me.
ROUND_DELAY = 0.8

try:
    from rich.console import Console
    from rich.layout import Layout
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.align import Align
except ImportError:  # pragma: no cover
    raise SystemExit(
        "The Rich TUI needs the 'rich' library (pip install rich).\n"
        "You can run the plain dashboard instead: python orchestrator.py"
    )


def _truncate(s, n=32):
    return s if len(s) <= n else s[: n - 1] + "…"


def _header(mock_mode):
    """Title header with a MOCK MODE badge when the app was unreachable."""
    title = Text("CyberRanger Arena — Red vs Blue", style="bold cyan")
    subtitle = Text("Scripted baseline · stage 1/8", style="dim")
    line = Text.assemble(title, "   ", subtitle)
    if mock_mode:
        line.append("   ")
        line.append(" [MOCK MODE] ", style="bold black on yellow")
    return Panel(Align.center(line), style="cyan")


def _table(rows):
    """Build the live results table from accumulated rows."""
    t = Table(expand=True)
    t.add_column("Round", justify="right", width=6)
    t.add_column("Red Payload")
    t.add_column("Category", width=9)
    t.add_column("Breached", width=9)
    t.add_column("Blue Flagged", width=13)
    t.add_column("Verdict", justify="center", width=8)
    for row in rows:
        action, result, blue_flagged, correct = row
        cat = action["category"]
        cat_style = "yellow" if cat == "benign" else "red"
        breached = (Text("BREACH", style="bold red") if result["breached"]
                    else Text("safe", style="green"))
        flagged = (Text("FLAGGED", style="cyan") if blue_flagged
                   else Text("allowed", style="dim"))
        verdict = (Text("✓", style="bold green") if correct
                   else Text("✗", style="bold red"))
        t.add_row(
            str(action["_round"]),
            _truncate(action["payload"]),
            Text(cat, style=cat_style),
            breached, flagged, verdict,
        )
    return t


def _metrics_panel(rows):
    """Big-number live metrics computed honestly from rows so far."""
    attacks = [r for r in rows if r[0]["category"] != "benign"]
    benign = [r for r in rows if r[0]["category"] == "benign"]
    detected = sum(1 for a in attacks if a[2])
    false_pos = sum(1 for b in benign if b[2])
    breaches = sum(1 for a in attacks if a[1]["breached"])
    det_rate = (detected / len(attacks) * 100) if attacks else 0.0
    fa_rate = (false_pos / len(benign) * 100) if benign else 0.0

    body = Text()
    body.append("Detection Rate\n", style="dim")
    body.append(f"  {det_rate:.0f}%  ", style="bold green")
    body.append(f"({detected}/{len(attacks)})\n\n", style="dim")
    body.append("False Alarm Rate\n", style="dim")
    body.append(f"  {fa_rate:.0f}%  ", style="bold yellow")
    body.append(f"({false_pos}/{len(benign)})\n\n", style="dim")
    body.append("Breaches\n", style="dim")
    body.append(f"  {breaches}/{len(attacks)}", style="bold red")
    return Panel(body, title="Live Metrics", border_style="magenta")


def _footer(rows_written):
    return Panel(
        Text(f"Dataset → runs/session.jsonl · {rows_written} rows written",
             style="dim"),
        style="green",
    )


def _render(mock_mode, rows, rows_written):
    """Assemble the full layout for the current state."""
    layout = Layout()
    layout.split_column(
        Layout(_header(mock_mode), size=3, name="header"),
        Layout(name="body"),
        Layout(_footer(rows_written), size=3, name="footer"),
    )
    layout["body"].split_row(
        Layout(_table(rows), name="table", ratio=3),
        Layout(_metrics_panel(rows), name="metrics", ratio=1),
    )
    return layout


def main(rounds=DEFAULT_ROUNDS):
    """Drive the arena and render it live with Rich."""
    red, blue = RedAgent(), BlueAgent()
    env = Environment()
    log = RunLogger()
    console = Console()

    rows = []
    with Live(_render(env.mock_mode, rows, 0), console=console,
              screen=False, auto_refresh=False) as live:
        for r in range(1, rounds + 1):
            action = red.next_action()
            action["_round"] = r  # display only
            result = env.execute(action)
            blue_flagged = blue.detect(action)

            ground_truth = ("benign" if action["category"] == "benign"
                            else "attack")
            is_attack = ground_truth == "attack"
            correct = (blue_flagged == is_attack)

            log.log_round(r, action, result["breached"], blue_flagged,
                          ground_truth, correct)
            rows.append((action, result, blue_flagged, correct))

            live.update(_render(env.mock_mode, rows, r), refresh=True)
            time.sleep(ROUND_DELAY)

        # Leave the final dashboard on screen for discussion.
        live.update(_render(env.mock_mode, rows, len(rows)), refresh=True)


if __name__ == "__main__":
    main()
