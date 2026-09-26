# CyberRanger

**Red-vs-Blue Co-Evolutionary Security Research System**

CyberRanger is an automated, quality-diversity security testing platform featuring MAP-Elites search on the red side, continual random forest learning on the blue side, human-in-the-loop analyst triage, and a strictly isolated Docker sandbox boundary.

---

## 🛡️ Core Architecture

```
                                  +---------------------------------------+
                                  |         HOST ORCHESTRATOR             |
                                  |   MAP-Elites Archive (Grid / QD)      |
                                  |   UCB1 Mutation Bandit                |
                                  |   Hall of Fame & Regression Suite     |
                                  |   SQLite Store (checkpoints.db)       |
                                  +-------------------+-------------------+
                                                      |
                          External LLM API (Optional) | Telemetry / Metrics
                          [claude-sonnet-4-6]         | (metrics.jsonl)
                                                      v
      ====================== STRICT SANDBOX BOUNDARY ======================
      Docker User-Defined Bridge: cyberranger_internal (internal: true)
      No default route, zero inbound/outbound external network access.
      ---------------------------------------------------------------------
            |                                           |
            v                                           v
      +---------------+ Mirror Traffic          +---------------+
      |  dvwa-target  |------------------------>| blue-detector |
      | (Target App)  |                         | (ML Detector) |
      +---------------+                         +---------------+
      =====================================================================
```

1. **Safety Boundary (§0)**: All attack traffic is contained inside `cyberranger_internal` (`internal: true`). Targets are hardcoded to the internal Docker service name `dvwa-target`.
2. **Quality-Diversity Search (§8)**: MAP-Elites archive partitioning the behavior space into cells indexed by `(VulnClass, InjectionPointCategory, EvasionTechnique, DetectorOutcome)`.
3. **Adaptive Operator Bandit (§4)**: UCB1 multi-armed bandit dynamically selecting among:
   - **Grammar mutation**: BNF-style grammar expansions parameterized by target fixtures.
   - **Crossover**: Structural splicing of parent payload templates.
   - **LLM semantic mutation**: Abstract structural niche proposal rendered deterministically.
4. **Scoring (§7)**: Response-diff compromise signals (SQLi multi-row dumps, unescaped XSS tokens, command output, LFI indicators) and blue-side detection confidence.
5. **Human Triage Portal (§9)**: Analyst review portal and REST API to promote candidate payloads to "confirmed" Red Elites.
6. **Blue Continual Learner (§10)**: Random forest retrained on confirmed exploits with hot-reloadable model artifacts.
7. **Hall of Fame & Regression (§11)**: Archives historical Red Elites and Blue Snapshots, continuously verifying detector stability against regression floors.
8. **Mission Control SOC Dashboard (`triage_ui/app.py`)**: Glassmorphic operations interface with interactive MAP-Elites heatmap grid, real-time co-evolution controls, telemetry charts, and payload inspector.

---

## 🚀 Quickstart

### 1. Start Sandbox Environment
```bash
docker compose up -d
```

### 2. Run Test Suite
```bash
python3 -m pytest tests/ -v
```

### 3. Launch Mission Control SOC Dashboard
```bash
python3 scripts/cyberranger_cli.py serve --port 8501
# Open http://127.0.0.1:8501 in your browser
```

---

## 💻 Unified CLI Usage (`scripts/cyberranger_cli.py`)

CyberRanger includes a unified command-line tool for operations:

```bash
# Check sandbox status, services health, and archive telemetry
python3 scripts/cyberranger_cli.py status

# Run co-evolution generation loop
python3 scripts/cyberranger_cli.py loop --generations 10 --resume

# List pending triage items
python3 scripts/cyberranger_cli.py triage list --status pending

# Confirm an exploit as a Red Elite
python3 scripts/cyberranger_cli.py triage confirm <ITEM_ID> --note "Verified SQLi dump"

# Retrain Blue Detector on confirmed exploits
python3 scripts/cyberranger_cli.py retrain

# Run regression testing against historical Red Elites
python3 scripts/cyberranger_cli.py regression

# Launch Mission Control Web UI
python3 scripts/cyberranger_cli.py serve --host 127.0.0.1 --port 8501
```

---

## 🌐 REST API Endpoints

The FastAPI service (`triage_ui/app.py`) provides the following endpoints:

| Endpoint | Method | Description |
|---|---|---|
| `/` | `GET` | Interactive Mission Control Web Dashboard |
| `/api/status` | `GET` | Health status of Docker sandbox, DVWA, Blue detector, and co-evolution stats |
| `/api/archive/matrix` | `GET` | MAP-Elites grid matrix data (Vulnerability Class × Evasion Technique) |
| `/api/metrics` | `GET` | Historical co-evolution log entries from `metrics.jsonl` |
| `/api/triage` | `GET` | List triage items with optional `status`, `vuln_class`, and `search` filters |
| `/api/triage/{id}` | `GET` | Get details for a specific triage item |
| `/api/triage/{id}` | `POST` | Submit human analyst review (`confirm`, `reject`, `duplicate`) |
| `/api/triage/batch` | `POST` | Batch review multiple items simultaneously |
| `/api/orchestrator/step` | `POST` | Trigger a single real-time generation step |
| `/api/orchestrator/epoch`| `POST` | Trigger an epoch of N generations with live telemetry |
| `/api/learning/retrain` | `POST` | Trigger Blue detector retraining on confirmed exploits |
| `/api/learning/regression`| `POST`| Run co-evolutionary regression pass |
| `/api/hall-of-fame` | `GET` | List historical Red Elites and Blue model snapshots |

---

## 🗄️ Persistence Schema (`checkpoints.db`)

All runtime state persists to SQLite:
- `checkpoints`: Generation snapshot, bandit arm weights, and population states.
- `genomes`: Rendered payloads, templates, mutation operators, and metadata.
- `triage_items`: Analyst review items with status transitions, reviewer notes, and timestamps.
- `archive_cells`: MAP-Elites cells indexed by behavioral descriptors and fitness scores.
- `hall_of_fame`: Historical Red Elites and Blue model paths for regression testing.
