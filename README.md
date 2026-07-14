# Ghrab VOC — Autonomous Vulnerability Operations Center

An AI-augmented Vulnerability Operations Center for Ghrab Financial Group (a
fictional financial-services lab). It ingests a Qualys-style vulnerability export
plus an enterprise CMDB, computes a deterministic context-aware risk score for
every finding, **autonomously discovers attack paths** from the reachability
graph, and layers a multi-provider agentic AI system on top for analyst-grade
narration, correlation, remediation, and compliance reasoning.

Two services:

- **`backend/`** — FastAPI. The deterministic engine (GRS scoring, ATT&CK-style
  capability classification, reachability-graph attack-path discovery) + the
  multi-provider agentic AI layer, exposed as a JSON/SSE API.
- **`frontend/`** — React + Vite + TypeScript SPA. A premium "command-center" UI
  with an interactive attack graph (React Flow), click-to-drill finding panels,
  streaming AI analyst, and live dashboards.

`_legacy/` holds the retired Streamlit prototype, kept for reference only.

---

## What makes it different

**The AI discovers attack paths — it doesn't read them from a script.**
The old prototype re-narrated attack chains that were hand-authored in a CSV
column. This version *derives* them:

1. **`backend/core/capability.py`** classifies each finding into ATT&CK-style
   capabilities (initial access, RCE, credential theft, privilege escalation,
   segmentation break, impact) from its CVSS vector, category, and description —
   never from the pre-authored `Attack_Path_Ref` column.
2. **`backend/core/attack_graph.py`** builds a reachability graph over the real
   asset inventory. Segmentation, credential-reuse, and domain-admin findings add
   edges; the engine enumerates chains from attacker-reachable entry points to the
   organization's crown jewels and ranks them by blast radius.
3. **`backend/agents/discovery_agent.py`** — an LLM agent validates, ranks, and
   narrates the candidate chains and surfaces non-obvious toxic combinations the
   pathfinder alone would miss.

The engine independently **re-discovers all six documented attack paths (A–F)**
from capability logic alone — verified by `backend/tests/test_rediscovery.py`,
which uses the documented `Attack_Path_Ref` column *only* as an offline oracle.

**The risk math is deterministic, not LLM-guessed.** The Ghrab Risk Score (GRS)
— CVSS + EPSS + KEV + Asset Criticality + Toxic-Combination blast radius, gated by
an exposure multiplier — is plain Python. The dashboard is fully usable with **zero
API keys**; AI agents explain and enrich, they never compute or override GRS.

**No single-vendor lock-in.** Each agent role can use a different provider
(Anthropic, OpenAI, Groq, Mistral, Gemini, DeepSeek, xAI) via
[litellm](https://github.com/BerriAI/litellm), with automatic fallback.

---

## Running it (local dev)

Prerequisites: Python 3.11+, Node 18+.

### 1. Backend

```bash
cd backend
python -m venv ../.venv && source ../.venv/bin/activate   # or reuse the repo .venv
pip install -r requirements.txt
cp ../.env.example ../.env   # optional — or set keys from the Settings tab at runtime
uvicorn main:app --reload --port 8000
```

The API serves on `http://localhost:8000` (`/api/health`, interactive docs at
`/docs`). It runs fully in deterministic mode with no API keys.

### 2. Frontend

```bash
cd frontend
npm install
npm run dev
```

Open the URL Vite prints (`http://localhost:5173`). The dev server proxies `/api`
to the backend on `:8000`. Add an LLM key any time from the **Settings** screen to
switch on the AI layer.

### One-command dev

```bash
./dev.sh      # starts backend + frontend together (Ctrl-C stops both)
```

---

## Running it (Docker)

```bash
docker compose up --build
```

Frontend on `http://localhost:8080`, backend on `http://localhost:8000`. Pass keys
via a `.env` file at the repo root (see `.env.example`).

---

## Bringing your own data

Replace the three files in `backend/data/` (`ghrab_vulnerabilities.csv`,
`ghrab_architecture.md`, `ghrab_risk_methodology.md`) with your own export and CMDB
doc, keeping the same column/table shapes described in `backend/core/ingestion.py`
and `backend/core/cmdb.py`. The EPSS/KEV tables in `backend/core/risk_engine.py`
are lab-specific — for a live pipeline, swap them for EPSS from the FIRST.org API
and KEV from CISA's published catalog.

## Project layout

```
backend/
  core/     deterministic engine — config, providers, cmdb, ingestion, risk_engine,
            capability (ATT&CK classification), attack_graph (path discovery)
  agents/   AI agents — discovery, correlation, remediation, compliance, triage/chat
  api/      FastAPI routers, serializers, SSE streams, shared state
  tests/    rediscovery acceptance gate
  main.py   FastAPI app
frontend/
  src/
    features/  overview, findings, attackpaths, correlation, teams, compliance, analyst, settings
    components/ layout, drawer, charts, AI dock, shared UI
    lib/       api client, types, hooks, formatting
_legacy/    retired Streamlit prototype (reference only)
```
