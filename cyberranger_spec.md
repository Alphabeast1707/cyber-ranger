# CyberRanger — Technical Specification

Red-vs-blue co-evolutionary security research system. Quality-diversity search on the
red side, continual learning on the blue side, isolated sandbox throughout.

Paste this whole document into your coding agent (Claude Code, Cursor, etc.) as the
spec for a fresh repo. Sections are ordered so a coding agent can build bottom-up:
persistence → sandbox → generation → evaluation → archive → learning → orchestrator.

---

## 0. Safety boundary (read first, build first)

This system must never have a network path to anything outside its own sandbox.

- All attack traffic stays inside a Docker user-defined bridge network with
  `internal: true` (no default route out, no internet access from any container).
- The only external network calls in the whole system are: (a) the LLM API call for
  the semantic mutation operator, made from the *orchestrator* process, never from
  inside the sandbox network, and (b) telemetry/logging to your own metrics store.
- DVWA and the blue detector service run as containers on the internal network only.
- No component ever gets a target hostname/IP as a runtime parameter — the target is
  hardcoded to the single sandbox service name (`dvwa-target`) resolved via Docker's
  internal DNS. This makes it structurally impossible to accidentally point the red
  population at anything else.
- A "confirmed vulnerability" label is a human action, never an automated one. The
  system labels things "candidate" until a person marks them "confirmed" in triage.

Build this boundary first and write a smoke test for it (spin up the sandbox network,
assert that a container inside it cannot resolve or reach any external host) before
writing a single line of the actual agents.

---

## 1. Repo structure

```
cyberranger/
├── docker-compose.yml            # sandbox network, dvwa-target, blue-detector
├── config/
│   └── default.yaml
├── cyberranger/
│   ├── __init__.py
│   ├── orchestrator.py           # main loop, ties everything together
│   ├── genome.py                 # Payload/Genome dataclass + serialization
│   ├── operators/
│   │   ├── grammar.py            # grammar-based mutation
│   │   ├── crossover.py
│   │   ├── llm_semantic.py       # LLM-driven semantic mutation
│   │   └── bandit.py             # operator-selection bandit
│   ├── population.py             # red agent population management
│   ├── sandbox_client.py         # fires payloads at dvwa-target + blue-detector
│   ├── scoring.py                # target-compromise + evasion signal extraction
│   ├── behavior.py               # behavior descriptor computation
│   ├── archive.py                # MAP-Elites archive
│   ├── triage.py                 # human review queue
│   ├── blue_learner.py           # blue detector retraining
│   ├── hall_of_fame.py           # regression archive + regression runner
│   ├── persistence.py            # checkpoint store (SQLite)
│   └── metrics.py                # coverage, QD-score, Elo, regression logging
├── blue_detector/                # the actual blue-side service (its own Docker image)
│   ├── Dockerfile
│   ├── app.py                    # FastAPI/Flask service DVWA traffic is mirrored to
│   └── model.py                  # classifier the blue_learner retrains
├── triage_ui/                    # minimal web UI for the human review queue
│   └── app.py
├── tests/
│   ├── test_sandbox_isolation.py # write this FIRST
│   ├── test_archive.py
│   ├── test_bandit.py
│   └── test_scoring.py
└── scripts/
    ├── run_generation_loop.py
    ├── run_learning_pass.py
    └── run_regression.py
```

---

## 2. Tech stack

| Concern | Choice | Why |
|---|---|---|
| Language | Python 3.11+ | everything below has mature Python bindings |
| Sandbox | Docker Compose, internal bridge network | isolation is a compose-file property, easy to audit |
| Target | DVWA (official Docker image) | standard, purpose-built vulnerable app |
| QD archive | `pyribs` | reference MAP-Elites implementation, saves reinventing insertion/replacement logic |
| Bandit | custom (UCB1 or Thompson sampling, ~30 lines) | only 3 arms, a library is overkill |
| Blue classifier | `scikit-learn` (start with `RandomForestClassifier` or `LogisticRegression`) | fast to retrain per learning pass, interpretable |
| LLM mutation | Anthropic API (`claude-sonnet-4-6` or later) | structured JSON output mode for new payload strategies |
| Persistence | SQLite (via `sqlmodel` or raw `sqlite3`) | single-file, zero-ops, fine at this scale |
| Metrics | JSON-lines file + optional Weights & Biases | keep it simple until you actually need dashboards |
| Triage UI | FastAPI + a single HTML page (or Streamlit) | this is an internal tool, not a product |
| Blue detector service | FastAPI, containerized separately from DVWA | must be independently deployable so retraining doesn't touch DVWA |

---

## 3. Core data schemas

```python
# cyberranger/genome.py
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import uuid

class VulnClass(str, Enum):
    SQLI = "sqli"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    SSRF = "ssrf"
    # extend as your DVWA config's modules grow

class EvasionTechnique(str, Enum):
    NONE = "none"
    ENCODING = "encoding"          # url/hex/unicode encoding
    CASE_VARIATION = "case_variation"
    COMMENT_INJECTION = "comment_injection"
    WHITESPACE_SUBSTITUTION = "whitespace_substitution"
    SEMANTIC_REWRITE = "semantic_rewrite"  # LLM-proposed, not in the fixed enum above —
                                            # store the actual technique name as free text
                                            # when this value is used

@dataclass
class Genome:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    generation: int = 0
    parent_ids: list[str] = field(default_factory=list)
    operator_used: str = ""          # "grammar" | "crossover" | "llm_semantic"
    vuln_class: VulnClass = VulnClass.SQLI
    injection_point: str = ""        # e.g. "login.username", "search.query_param"
    evasion_technique: EvasionTechnique = EvasionTechnique.NONE
    evasion_technique_detail: Optional[str] = None  # free text for LLM-proposed techniques
    payload_template: str = ""       # abstract structure, not the literal string
    rendered_payload: str = ""       # the literal string actually sent
    metadata: dict = field(default_factory=dict)

@dataclass
class TrialResult:
    genome_id: str
    target_compromised: bool
    compromise_confidence: float     # 0-1, from response-diff heuristics
    detector_flagged: bool
    detector_confidence: float       # 0-1, from blue detector's own score
    detector_rule_fired: Optional[str]
    response_signature: str          # hashable fingerprint of the raw response, for dedup
    latency_ms: int
    raw_response_excerpt: str        # truncated, for triage review only

@dataclass
class BehaviorDescriptor:
    """The tuple that determines which archive cell a genome belongs to."""
    vuln_class: VulnClass
    injection_point_category: str    # coarsened injection_point, e.g. "auth_form" | "search" | "url_param"
    evasion_technique: EvasionTechnique
    detector_outcome: str            # "undetected" | "flagged_low_confidence" | "flagged_high_confidence"

    def cell_key(self) -> tuple:
        return (self.vuln_class, self.injection_point_category,
                self.evasion_technique, self.detector_outcome)
```

```python
# cyberranger/triage.py
@dataclass
class TriageItem:
    id: str
    genome: Genome
    trial_result: TrialResult
    behavior_descriptor: BehaviorDescriptor
    archive_cell_status: str   # "new_cell" | "replaced_incumbent"
    fitness: float
    status: str = "pending"    # "pending" | "confirmed" | "rejected" | "duplicate"
    reviewer_note: Optional[str] = None
    reviewed_at: Optional[str] = None
```

```python
# cyberranger/hall_of_fame.py
@dataclass
class HallOfFameEntry:
    id: str
    entry_type: str            # "red_elite" | "blue_snapshot"
    genome: Optional[Genome]   # set if entry_type == "red_elite"
    blue_model_path: Optional[str]  # set if entry_type == "blue_snapshot"
    retired_at_generation: int
    confirmed_by: str          # triage reviewer identifier
```

---

## 4. Mutation bandit

Three arms: `grammar`, `crossover`, `llm_semantic`. Use UCB1 for simplicity —
Thompson sampling is a fine upgrade later but adds complexity you don't need yet.

```python
# cyberranger/operators/bandit.py
import math

class OperatorBandit:
    def __init__(self, arms: list[str]):
        self.arms = arms
        self.counts = {a: 0 for a in arms}
        self.total_reward = {a: 0.0 for a in arms}
        self.t = 0

    def select(self) -> str:
        self.t += 1
        # play every arm once first
        for a in self.arms:
            if self.counts[a] == 0:
                return a
        def ucb(a):
            mean = self.total_reward[a] / self.counts[a]
            bonus = math.sqrt(2 * math.log(self.t) / self.counts[a])
            return mean + bonus
        return max(self.arms, key=ucb)

    def update(self, arm: str, reward: float):
        """reward should be: 1.0 for a new archive cell, 0.3 for beating an
        incumbent, 0.0 for no archive improvement. Clip to [0, 1]."""
        self.counts[arm] += 1
        self.total_reward[arm] += reward
```

Reward calculation happens in the orchestrator right after an archive insertion
attempt (see §8) — the bandit module itself stays generic and reward-agnostic.

---

## 5. Generation operators

**Grammar mutation** — maintain a small BNF-style grammar per `VulnClass` describing
the *structure* of a payload (tokens, boundary markers, comment insertion points,
encoding wrap points) rather than a fixed string list. The mutation operator picks a
production rule at random and re-expands it. Keep the actual payload strings/templates
in a local, version-controlled fixtures file scoped to your DVWA instance — don't
hardcode literal exploit strings into the operator logic itself, so the grammar can be
extended per-target without code changes.

**Crossover** — standard genetic crossover: take two parent genomes from the archive
(sampled preferentially from adjacent or under-filled cells), splice their
`payload_template` structures at a compatible boundary point.

**LLM semantic mutation** — this is the operator that produces qualitatively new
approaches rather than parameter variations. Call pattern:

```python
# cyberranger/operators/llm_semantic.py
SYSTEM_PROMPT = """You are proposing new attack STRUCTURES (not payloads) for an
authorized security research system attacking an isolated, intentionally-vulnerable
DVWA instance. Given the current archive coverage (which vulnerability classes,
injection points, and evasion technique combinations are already well-explored),
propose a new structural approach not yet represented. Output JSON only:
{"vuln_class": ..., "injection_point_category": ..., "evasion_technique": ...,
 "structural_description": "abstract description of the technique, no literal payload",
 "rationale": "why this is likely to be a distinct niche from what's covered"}
"""

def propose_new_strategy(archive_summary: dict, client) -> dict:
    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=500,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": f"Current archive coverage:\n{archive_summary}"}],
    )
    return parse_json(response.content[0].text)
```

The LLM proposes the *structural approach*; a downstream deterministic renderer
(reusing the grammar module's expansion logic) turns that structural description into
an actual payload string. This keeps the LLM out of the business of emitting literal
exploit strings directly and gives you an auditable translation step in between.

---

## 6. Sandbox

`docker-compose.yml` skeleton:

```yaml
networks:
  cyberranger_internal:
    internal: true   # no route to the outside — this is the load-bearing line

services:
  dvwa-target:
    image: vulnerables/web-dvwa
    networks: [cyberranger_internal]
    # no ports: mapping to the host in the default profile — expose only for manual debugging

  blue-detector:
    build: ./blue_detector
    networks: [cyberranger_internal]
    volumes:
      - ./blue_detector/models:/app/models   # swapped by blue_learner after retraining
```

`sandbox_client.py` sends each rendered payload to `dvwa-target` and mirrors the same
request/response pair to `blue-detector` for scoring, entirely inside the internal
network — the orchestrator process itself sits outside the sandbox network and only
talks to it through the compose-exposed internal service names.

---

## 7. Scoring — two independent signals

```python
# cyberranger/scoring.py
def score_target_compromise(response) -> tuple[bool, float]:
    """Heuristics: DB error strings, unexpected row counts, reflected script tags
    rendered unescaped, command output patterns, file contents leaking. Return
    (compromised: bool, confidence: float)."""
    ...

def score_detection(detector_response) -> tuple[bool, float, str | None]:
    """Read blue-detector's own verdict + confidence + which rule/feature fired."""
    ...

def combined_fitness(compromise_conf: float, evasion_conf: float) -> float:
    """A payload that compromises AND evades is highest fitness. One that compromises
    but gets flagged is still useful (tells you the detector needs a rule that's
    currently missing entirely). Suggested starting formula:
        fitness = compromise_conf * (0.5 + 0.5 * (1 - evasion_conf))
    Tune once you have real data — don't over-engineer this before you have signal."""
    return compromise_conf * (0.5 + 0.5 * (1 - evasion_conf))
```

---

## 8. MAP-Elites archive

```python
# cyberranger/archive.py
class Archive:
    def __init__(self):
        self.cells: dict[tuple, tuple[Genome, TrialResult, float]] = {}

    def try_insert(self, genome, result, descriptor, fitness) -> str:
        """Returns 'new_cell', 'replaced_incumbent', or 'rejected'."""
        key = descriptor.cell_key()
        if key not in self.cells:
            self.cells[key] = (genome, result, fitness)
            return "new_cell"
        _, _, incumbent_fitness = self.cells[key]
        if fitness > incumbent_fitness:
            self.cells[key] = (genome, result, fitness)
            return "replaced_incumbent"
        return "rejected"

    def coverage(self, total_possible_cells: int) -> float:
        return len(self.cells) / total_possible_cells

    def qd_score(self) -> float:
        return sum(fitness for _, _, fitness in self.cells.values())

    def summary_for_llm(self) -> dict:
        """Coarsened view of filled cells, for the LLM semantic mutator's prompt —
        counts per vuln_class/evasion_technique combo, not raw payloads."""
        ...
```

Reward-to-bandit mapping (used in the orchestrator loop):
`new_cell → 1.0`, `replaced_incumbent → 0.3`, `rejected → 0.0`.

If you adopt `pyribs` instead of the hand-rolled version above, its `GridArchive`
maps directly onto this same cell-key/fitness model — swap the class, keep the
descriptor and reward logic identical.

---

## 9. Human triage

Minimal viable version: a FastAPI endpoint + one HTML page listing pending
`TriageItem`s (genome's abstract structure, both confidence scores, response
excerpt, archive cell status) with **Confirm** / **Reject** / **Mark duplicate**
buttons. Confirming a `TriageItem`:

1. Sets `status = "confirmed"`.
2. Enqueues the genome for the next `blue_learner` retraining batch.
3. Writes a `HallOfFameEntry(entry_type="red_elite", ...)`.

Don't gate the generation loop on triage throughput — new cells keep contributing
bandit reward the moment they're inserted, regardless of triage status. Triage only
gates what becomes blue-learner training data and what counts as a "confirmed
finding" in your reporting.

---

## 10. Blue learner

```python
# cyberranger/blue_learner.py
from sklearn.ensemble import RandomForestClassifier

def retrain(confirmed_items: list[TriageItem], existing_model=None):
    X, y = build_feature_matrix(confirmed_items)   # features: request structure,
                                                     # token n-grams, encoding markers —
                                                     # NOT raw payload strings as-is,
                                                     # to encourage generalization
    model = RandomForestClassifier(n_estimators=200, class_weight="balanced")
    model.fit(X, y)
    return model  # caller saves to blue_detector/models/, service hot-reloads
```

Retrain on a fixed cadence (every learning pass, §11), not on every single confirmed
item — batch it so the blue detector doesn't thrash on noisy single examples.

---

## 11. Orchestrator — the actual main loop

```python
# cyberranger/orchestrator.py

def generation_step(bandit, population, sandbox, archive, config):
    arm = bandit.select()
    parents = population.sample_parents(archive, n=config.offspring_per_gen)
    offspring = apply_operator(arm, parents)          # grammar/crossover/llm_semantic
    for genome in offspring:
        result = sandbox.fire(genome)
        compromise_conf = score_target_compromise(result)
        evasion_conf = score_detection(result)
        fitness = combined_fitness(compromise_conf, evasion_conf)
        descriptor = compute_behavior_descriptor(genome, result)
        outcome = archive.try_insert(genome, result, descriptor, fitness)
        reward = {"new_cell": 1.0, "replaced_incumbent": 0.3, "rejected": 0.0}[outcome]
        bandit.update(arm, reward)
        if outcome != "rejected":
            enqueue_triage(genome, result, descriptor, outcome, fitness)
    population.advance_generation(offspring)
    persistence.checkpoint(population, bandit, generation=population.gen)

def learning_pass(triage_queue, blue_learner, hall_of_fame, archive, blue_detector):
    confirmed = triage_queue.pull_confirmed_since_last_pass()
    if confirmed:
        new_model = blue_learner.retrain(confirmed)
        hall_of_fame.archive_blue_snapshot(blue_detector.current_model_path())
        blue_detector.deploy(new_model)
        for item in confirmed:
            hall_of_fame.archive_red_elite(item.genome)

def regression_pass(hall_of_fame, population, blue_detector, metrics):
    blue_pass_rate = hall_of_fame.test_blue_against_all_red_elites(blue_detector)
    red_pass_rate = hall_of_fame.test_population_against_retired_blue(population)
    metrics.log(blue_regression=blue_pass_rate, red_regression=red_pass_rate)
    if blue_pass_rate < config.regression_floor:
        alert("blue detector regressed against historical red techniques")

def main_loop(config):
    # ... wire up all components from config, then:
    for gen in range(config.max_generations):
        generation_step(bandit, population, sandbox, archive, config)
        if gen % config.learning_pass_interval == 0:
            learning_pass(triage_queue, blue_learner, hall_of_fame, archive, blue_detector)
            regression_pass(hall_of_fame, population, blue_detector, metrics)
        if gen % config.metrics_interval == 0:
            metrics.log(coverage=archive.coverage(config.total_possible_cells),
                        qd_score=archive.qd_score())
        if gen % config.scaling_check_interval == 0 and coverage_has_plateaued(metrics):
            notify("archive coverage has plateaued — consider increasing target complexity")
```

---

## 12. Config file

```yaml
# config/default.yaml
sandbox:
  network_name: cyberranger_internal
  target_service: dvwa-target
  detector_service: blue-detector

generation:
  offspring_per_gen: 20
  max_generations: 100000

bandit:
  arms: [grammar, crossover, llm_semantic]

archive:
  vuln_classes: [sqli, xss, command_injection, path_traversal, ssrf]
  injection_point_categories: [auth_form, search, url_param, file_upload, cookie]
  evasion_techniques: [none, encoding, case_variation, comment_injection, whitespace_substitution]
  detector_outcomes: [undetected, flagged_low_confidence, flagged_high_confidence]
  # total_possible_cells = product of the above list lengths

learning:
  learning_pass_interval: 50       # generations between learning passes
  regression_floor: 0.9            # alert if blue's regression pass rate drops below this

metrics:
  metrics_interval: 10
  scaling_check_interval: 500
  backend: jsonlines               # or "wandb"

llm:
  model: claude-sonnet-4-6
  max_tokens: 500
```

---

## 13. Metrics to log every pass

`generation`, `archive_coverage`, `qd_score`, `bandit_arm_weights`, `blue_regression_pass_rate`,
`red_regression_pass_rate`, `mean_episodes_to_first_compromise_per_class`, `pending_triage_count`.

Log as JSON lines (`metrics.jsonl`) at minimum — trivial to load into pandas later,
zero infrastructure to stand up.

---

## 14. Build order (map to milestones)

1. `test_sandbox_isolation.py` passing — network boundary proven before anything else.
2. `docker-compose up` with DVWA reachable only from inside the network; a trivial
   blue-detector stub that always returns "not flagged."
3. `Genome`, `TrialResult`, grammar operator, `sandbox_client.fire()` — single-operator,
   no bandit yet, log everything to stdout.
4. `Archive` + behavior descriptor — confirm cells fill sensibly on real traffic.
5. `OperatorBandit` wired to archive reward — confirm arm weights shift when you
   artificially cripple one operator.
6. `crossover` and `llm_semantic` operators added.
7. Triage endpoint (can be a CLI script before it's a web UI).
8. `blue_learner` retraining loop + blue-detector hot-reload.
9. `hall_of_fame` + regression pass.
10. Metrics logging + a plateau-detection check.

Each step should have a passing test before you move to the next — this is exactly
the kind of multi-component system where skipping the isolation test or the archive
test comes back to bite you three components later.

---

## Prompt to paste into your coding agent

```
Build a Python project called CyberRanger from the attached spec
(cyberranger_spec.md). Follow the build order in §14 exactly, one milestone at a
time, with a passing test before moving to the next milestone. Start with
§0 (safety boundary) and §1 (repo structure) — set up the Docker Compose sandbox
with an internal-only network and write tests/test_sandbox_isolation.py first,
and don't proceed to milestone 2 until that test passes. Use the exact data
schemas in §3 as your dataclasses. Ask me before making any architectural
decision not already specified in the document.
```
