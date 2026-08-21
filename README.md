# CyberRanger Arena

**Two security AIs in an arms race.** A Red agent throws real web exploits at a
local sandboxed vulnerable app; a Blue agent tries to detect them. When Red
gets a hit past Blue, Blue *learns a new rule*. When Blue catches Red, Red
*mutates* its payload to evade. You watch the whole thing co-evolve live in the
browser.

This is **stage 1 of 8** of a co-evolution project. No LLMs, no ML, no GPU yet —
just honest rule-based agents behind clean seams where the learning cores plug
in next. Every number on screen is computed from real matches; nothing is faked.

---

## Quick start (the demo)

```bash
# 1. install Python deps with uv
uv sync

# 2. start the real target app (see SETUP.md)
docker compose up -d           # DVWA on http://localhost:8080

# 3. one-time DVWA database setup (idempotent, safe to re-run)
uv run python setup_dvwa.py    # confirms real breaches on all 4 vuln classes

# 4. run the live web dashboard
uv run python server.py         # opens http://localhost:8000 in your browser
```

That's the show: a React/shadcn dashboard (in `web/`) with a Red-vs-Blue
dominance meter, live metrics, an "arms race" chart, and a tabbed engagement
log — **Combat**, plus attacker's-eye (**Red**) and defender's-eye (**Blue**)
consoles. The prebuilt UI is committed to `web/dist`, so step 4 works right
after clone without Node.

**No DVWA running?** It still works — the environment falls back to
**SANDBOX (mock) mode** (clearly badged) and simulates plausible responses, so
the demo never hard-fails in front of an audience.

### Rebuilding the UI (only if you change `web/src`)

```bash
cd web && npm install && npm run build
# or hot-reload dev: npm run dev  (proxies /stream to the backend on :8000)
```

### Other ways to run it

```bash
uv run python coevolution.py   # same arms race, headless in the terminal
uv run python orchestrator.py  # the original stage-1 single-round loop
uv run python arena_tui.py     # stage-1 Rich terminal dashboard
```

### Other ways to run it

```bash
uv run python coevolution.py   # same arms race, headless in the terminal
uv run python orchestrator.py  # the original stage-1 single-round loop
uv run python arena_tui.py     # stage-1 Rich terminal dashboard
```

---

## What you're watching

Each **generation**:

1. **Red** proposes a batch of payloads (SQLi, XSS, command injection, path
   traversal) plus one benign probe.
2. The **environment** (`dvwa_env.py`) fires each at its DVWA endpoint and
   reports whether it **breached**.
3. **Blue** (`coevo_agents.py`) tries to **detect** each with its regex ruleset.
4. Any attack that breached *without being flagged* → **Blue learns a new rule.**
5. **Red evolves:** the payloads that evaded Blue survive and spawn mutated
   children (comment-injection, case-flipping, URL-encoding, vector pivots).

Over ~20 generations you see a real arms race: Blue's detection climbs as it
learns, then Red finds fresh evasions. The typical arc — a static Blue
eventually gets out-evolved — is exactly the motivation for stage 2.

---

## Safety & containment

This is a **sandboxed academic exercise** against a deliberately-vulnerable
practice app (DVWA).

- **Everything targets `localhost` / `127.0.0.1` only. No external hosts.**
- `dvwa_env.py` (and stage-1 `environment.py`) assert this on every request via
  `_assert_localhost()` and raise a clear error for any non-local target.
- Only ever expose DVWA on your local machine.

---

## The seams — where the smarter cores plug in next

Stage 1 exists to get the *interfaces* right so later stages are drop-in:

- **LLM reasoning cores.** `EvolvingRedAgent.propose/evolve` and
  `EvolvingBlueAgent.detect/learn` carry `# LLM ... plugs in here` markers.
  Swap the mutation operators for an LLM attacker, and the regex learner for an
  LLM that reasons about intent — the engine and dashboard don't change.
- **RL retraining loop.** `coevolution.run()` already emits a per-generation
  reward signal (evasion rate, detection rate, breaches). A future loop reads
  those, updates each agent's policy, and feeds the next generation back through
  the same engine — closing the co-evolution loop.

---

## Files

| File | Role |
|------|------|
| `server.py` | FastAPI + SSE server for the live web dashboard **(main demo)** |
| `web/` | React + shadcn/Tailwind frontend (source in `web/src`, prebuilt in `web/dist`) |
| `setup_dvwa.py` | One-command DVWA database init + live-breach verification |
| `coevolution.py` | The generation engine / arms-race loop |
| `coevo_agents.py` | Evolving Red & Blue agents (mutation + rule-learning seams) |
| `payloads.py` | Attack library + mutation operators |
| `dvwa_env.py` | Authenticated DVWA target, per-category breach heuristics, mock fallback, localhost guard |
| `orchestrator.py` · `arena_tui.py` | Original stage-1 single-round demo + Rich TUI |
| `red_agent.py` · `blue_agent.py` · `environment.py` · `logger.py` | Stage-1 modules |
| `docker-compose.yml` · `SETUP.md` | Brings up DVWA + exact setup steps |
| `pyproject.toml` · `uv.lock` | uv-managed Python dependencies |
