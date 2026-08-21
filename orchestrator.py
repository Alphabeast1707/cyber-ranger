"""CyberRanger Arena — main entry point (plain console).

Runs N rounds of a scripted Red-vs-Blue loop against a local sandboxed
DVWA instance (or a mock fallback). Each round:

    Red picks an action -> Environment executes -> Blue attempts detection
    -> compare Blue's call against ground truth -> log the labeled result.

Run:  python orchestrator.py
"""

import sys

from red_agent import RedAgent
from blue_agent import BlueAgent
from environment import Environment
from logger import RunLogger

DEFAULT_ROUNDS = 5

# Optional color; degrade gracefully if colorama is missing.
try:
    from colorama import Fore, Style, init as _color_init
    _color_init()
    C_RED, C_GREEN, C_YELLOW = Fore.RED, Fore.GREEN, Fore.YELLOW
    C_CYAN, C_DIM, C_RESET = Fore.CYAN, Style.DIM, Style.RESET_ALL
    C_BOLD = Style.BRIGHT
except ImportError:  # no colorama -> empty codes
    C_RED = C_GREEN = C_YELLOW = C_CYAN = C_DIM = C_RESET = C_BOLD = ""


def run(rounds=DEFAULT_ROUNDS):
    """Execute the arena for `rounds` rounds and print a live + summary view."""
    red = RedAgent()
    blue = BlueAgent()
    env = Environment()
    log = RunLogger()

    print(f"{C_BOLD}{C_CYAN}=== CyberRanger Arena — Red vs Blue ==={C_RESET}")
    if env.mock_mode:
        print(f"{C_YELLOW}{C_BOLD}[MOCK MODE] DVWA unreachable at "
              f"{env.base_url} — simulating responses.{C_RESET}")
    else:
        print(f"{C_DIM}Target: {env.base_url} (live){C_RESET}")
    print()

    records = []
    for r in range(1, rounds + 1):
        action = red.next_action()
        result = env.execute(action)
        blue_flagged = blue.detect(action)

        ground_truth = "benign" if action["category"] == "benign" else "attack"
        is_attack = ground_truth == "attack"
        # Correct = Blue flags attacks and lets benign pass.
        correct = (blue_flagged == is_attack)

        log.log_round(r, action, result["breached"], blue_flagged,
                      ground_truth, correct)
        records.append((action, result, blue_flagged, correct, is_attack))

        _print_round(r, action, result, blue_flagged, correct)

    _print_summary(records, log.path)
    return records


def _cat_color(category):
    return C_YELLOW if category == "benign" else C_RED


def _print_round(r, action, result, blue_flagged, correct):
    """Pretty-print a single round to the console."""
    verdict = f"{C_GREEN}✓{C_RESET}" if correct else f"{C_RED}✗{C_RESET}"
    cat_c = _cat_color(action["category"])
    breached = (f"{C_RED}BREACH{C_RESET}" if result["breached"]
                else f"{C_GREEN}safe{C_RESET}")
    flagged = (f"{C_CYAN}FLAGGED{C_RESET}" if blue_flagged
               else f"{C_DIM}allowed{C_RESET}")

    print(f"{C_BOLD}Round {r}{C_RESET}  {verdict}  "
          f"[{cat_c}{action['category']}{C_RESET}] {action['name']}")
    print(f"   Red payload : {C_DIM}{action['payload']}{C_RESET}")
    print(f"   App [{result['status_code']}] : "
          f"{result['response_snippet']}  -> {breached}")
    print(f"   Blue        : {flagged}")
    print()


def _print_summary(records, path):
    """Compute metrics honestly from logged records and print the summary."""
    rounds = len(records)
    attacks = [rec for rec in records if rec[4]]
    benign = [rec for rec in records if not rec[4]]

    detected = sum(1 for a in attacks if a[2])          # blue_flagged
    false_pos = sum(1 for b in benign if b[2])          # flagged benign
    breaches = sum(1 for a in attacks if a[1]["breached"])

    det_rate = (detected / len(attacks) * 100) if attacks else 0.0
    fa_rate = (false_pos / len(benign) * 100) if benign else 0.0

    print(f"{C_BOLD}{C_CYAN}=== CyberRanger Arena — Session Summary ==="
          f"{C_RESET}")
    print(f"Rounds: {rounds} | Attacks: {len(attacks)} | Benign: {len(benign)}")
    print(f"Detected: {detected}/{len(attacks)}   "
          f"Detection rate: {det_rate:.0f}%")
    print(f"False positives: {false_pos}   "
          f"False alarm rate: {fa_rate:.0f}% ({false_pos}/{len(benign)} benign)")
    print(f"Breaches: {breaches}/{len(attacks)}")
    print(f"Dataset written: {path} ({rounds} labeled rows)")


if __name__ == "__main__":
    n = DEFAULT_ROUNDS
    if len(sys.argv) > 1:
        try:
            n = int(sys.argv[1])
        except ValueError:
            pass
    run(n)
