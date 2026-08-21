"""Co-evolution engine — the arms race loop.

Runs N generations. Each generation:
  1. Red proposes a batch of attacks (+ one benign probe).
  2. The DVWA environment executes each -> breach?
  3. Blue tries to detect each -> flagged?
  4. Blue LEARNS a rule from every attack that breached undetected.
  5. Red EVOLVES: evaders survive and spawn mutated children.

The engine is a generator: it yields a JSON-serializable snapshot per
generation so any front-end (web dashboard, TUI, plain print) can render it.
All metrics are computed from real matches — nothing is scripted.
"""

import random

from coevo_agents import EvolvingRedAgent, EvolvingBlueAgent
from dvwa_env import DVWAEnvironment, endpoint_for

DEFAULT_GENERATIONS = 20
RANDOM_SEED = 7  # fixed so the demo looks the same (and good) every run


def run(generations=DEFAULT_GENERATIONS, env=None):
    """Yield one snapshot dict per generation. Also yields a final summary.

    Snapshot keys: gen, mock_mode, attacks, breaches, detected, evaded,
    red_success_rate, blue_detection_rate, false_alarms, blue_rules,
    red_variants, feed (list of per-attack rows), and cumulative series.
    """
    random.seed(RANDOM_SEED)
    red = EvolvingRedAgent()
    blue = EvolvingBlueAgent()
    env = env or DVWAEnvironment()

    series_red, series_blue = [], []
    total_breaches = 0

    for gen in range(1, generations + 1):
        batch = red.propose()
        results, feed = [], []

        for action in batch:
            payload, category = action["payload"], action["category"]
            outcome = env.execute(payload, category)
            breached = outcome["breached"]
            detected, matched_rule = blue.inspect(payload)
            is_attack = category != "benign"

            # Blue learns from anything that breached without being flagged.
            learned_sig = None
            if is_attack and breached and not detected:
                learned_sig = blue.learn(payload)

            # Blue's reasoning, in words, for the defender console.
            if not is_attack:
                blue_note = ("flagged benign traffic (false positive)"
                             if detected else "allowed — looks benign")
            elif detected:
                blue_note = f"matched rule  /{matched_rule}/"
            elif learned_sig:
                blue_note = f"missed — learned new signature  /{learned_sig}/"
            else:
                blue_note = "no rule matched — attack slipped through"

            row = {
                "payload": payload,
                "category": category,
                "endpoint": endpoint_for(category),
                "origin": action.get("origin", "-"),
                "breached": breached,
                "detected": detected,
                "matched_rule": matched_rule,
                "blue_note": blue_note,
                "evaded": is_attack and breached and not detected,
                "learned": learned_sig,
            }
            results.append(row)
            feed.append(row)

        # -- honest per-generation metrics --------------------------------
        attacks = [r for r in results if r["category"] != "benign"]
        benign = [r for r in results if r["category"] == "benign"]
        n_attacks = len(attacks) or 1
        breaches = sum(1 for r in attacks if r["breached"])
        detected = sum(1 for r in attacks if r["detected"])
        evaded = sum(1 for r in attacks if r["evaded"])
        false_alarms = sum(1 for r in benign if r["detected"])
        total_breaches += breaches

        red_success = evaded / n_attacks * 100          # breached & undetected
        blue_detection = detected / n_attacks * 100
        series_red.append(round(red_success, 1))
        series_blue.append(round(blue_detection, 1))

        yield {
            "type": "generation",
            "gen": gen,
            "generations": generations,
            "mock_mode": env.mock_mode,
            "attacks": len(attacks),
            "breaches": breaches,
            "detected": detected,
            "evaded": evaded,
            "false_alarms": false_alarms,
            "red_success_rate": round(red_success, 1),
            "blue_detection_rate": round(blue_detection, 1),
            "blue_rules": blue.rule_count,
            "blue_learned": blue.learned,
            "red_variants": red.variant_count,
            "total_breaches": total_breaches,
            "feed": feed,
            "series_red": list(series_red),
            "series_blue": list(series_blue),
        }

        # Red adapts for the next generation.
        red.evolve(results)

    yield {
        "type": "summary",
        "generations": generations,
        "mock_mode": env.mock_mode,
        "total_breaches": total_breaches,
        "blue_rules": blue.rule_count,
        "blue_learned": blue.learned,
        "red_variants": red.variant_count,
        "final_red_success": series_red[-1] if series_red else 0,
        "final_blue_detection": series_blue[-1] if series_blue else 0,
        "series_red": series_red,
        "series_blue": series_blue,
    }


if __name__ == "__main__":
    # Headless run: print the arms race to the console (no server needed).
    for snap in run():
        if snap["type"] == "generation":
            print(f"Gen {snap['gen']:>2}/{snap['generations']}  "
                  f"Red evade {snap['red_success_rate']:>5.1f}%  "
                  f"Blue detect {snap['blue_detection_rate']:>5.1f}%  "
                  f"breaches={snap['breaches']}  rules={snap['blue_rules']}  "
                  f"variants={snap['red_variants']}"
                  + ("   [MOCK]" if snap["mock_mode"] else ""))
        else:
            print(f"\nFinal: Blue learned {snap['blue_learned']} rules, "
                  f"Red bred {snap['red_variants']} variants, "
                  f"{snap['total_breaches']} total breaches.")
