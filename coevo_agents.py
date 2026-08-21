"""Evolving Red and Blue agents for the co-evolution arena.

Adaptive versions of the stage-1 agents that carry state across generations so
an arms race can emerge — and that expose *why* they act, so the UI can show a
detailed Red console (attack technique) and Blue console (rule reasoning).

  * EvolvingRedAgent keeps a payload population and mutates the ones that
    breach AND evade Blue.        # LLM attacker policy plugs in here
  * EvolvingBlueAgent learns a new detection rule every time something breaches
    without being flagged.        # LLM reasoning plugs in here

All rule-based and honest — metrics come from real matching, not scripting.
"""

import random
import re

import payloads


class EvolvingRedAgent:
    """Maintains a payload population and evolves evasive variants."""

    def __init__(self, pop_size=8):
        self.pop_size = pop_size
        self.population = []
        for cat, plist in payloads.BASE_PAYLOADS.items():
            for p in plist:
                self.population.append(
                    {"payload": p, "category": cat, "origin": "base exploit"})
        random.shuffle(self.population)
        self.variant_count = 0

    def propose(self):
        """Return this generation's batch of attacks (+ one benign probe)."""
        batch = list(self.population[: self.pop_size])
        batch.append({"payload": random.choice(payloads.BENIGN),
                      "category": "benign", "origin": "benign probe"})
        return batch

    def evolve(self, results):
        """Keep the evaders, mutate them, and record how each variant was made.

        results: dicts with payload, category, breached, detected.
        """
        evaders = [r for r in results
                   if r["category"] != "benign"
                   and r["breached"] and not r["detected"]]
        caught = [r for r in results
                  if r["category"] != "benign" and r["detected"]]

        new_pop = []
        for e in evaders:  # elites survive unchanged
            new_pop.append({"payload": e["payload"], "category": e["category"],
                            "origin": "elite · still evading"})
        for e in evaders + caught:  # each spawns a mutated child
            child, technique = payloads.mutate(e["payload"], e["category"])
            new_pop.append({"payload": child, "category": e["category"],
                            "origin": f"evasion · {technique}"})
            self.variant_count += 1

        if not new_pop:  # Blue caught everything: inject fresh probes
            for cat, plist in payloads.BASE_PAYLOADS.items():
                child, technique = payloads.mutate(plist[0], cat)
                new_pop.append({"payload": child, "category": cat,
                                "origin": f"re-probe · {technique}"})
                self.variant_count += 1

        random.shuffle(new_pop)
        self.population = new_pop[: max(self.pop_size, 6)]


class EvolvingBlueAgent:
    """Regex detector that learns new signatures from missed breaches."""

    # Human-readable names for the starting rules and the learnable vocabulary.
    def __init__(self):
        self._rules = [
            (re.compile(r"\bunion\b.*\bselect\b", re.I), r"union.*select"),
            (re.compile(r"<\s*script", re.I), r"<script"),
            (re.compile(r"\.\./", re.I), r"../"),
        ]
        self.learned = 0
        self._vocab = [
            r"or\s+['\"]?1['\"]?\s*=\s*['\"]?1", r"\bor\b\s*1=1",
            r"onerror\s*=", r"onload\s*=", r"<\s*svg", r"<\s*img",
            r"<\s*iframe", r"<\s*body", r";\s*id", r"\|\s*whoami",
            r"&&", r"`", r"\$\(", r"etc/passwd", r"%2f", r"/\*\*/",
            r"\|\|", r"sleep\s*\(",
        ]

    def normalize(self, payload):
        """Strip common obfuscation so literal rules still bite."""
        s = payload.lower()
        s = s.replace("/**/", "")
        s = s.replace("%27", "'").replace("%2f", "/")
        return s

    def inspect(self, payload):
        """Return (detected, matched_signature|None). The Blue reasoning seam."""
        norm = self.normalize(payload)
        for rule, sig in self._rules:
            if rule.search(norm):
                return True, sig
        return False, None

    def detect(self, payload):
        detected, _ = self.inspect(payload)
        return detected

    def learn(self, payload):
        """Add the most specific known signature present in a missed breach."""
        norm = self.normalize(payload)
        for sig in self._vocab:
            if re.search(sig, norm, re.I) and not self._known(sig):
                self._rules.append((re.compile(sig, re.I), sig))
                self.learned += 1
                return sig
        return None

    def _known(self, sig):
        return any(s == sig for _, s in self._rules)

    @property
    def rule_count(self):
        return len(self._rules)
