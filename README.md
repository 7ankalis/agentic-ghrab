# VMC — Vulnerability Management Center

Multi-agent, provider-agnostic exposure management platform. See
[`docs/VMC_ARCHITECTURE_OVERVIEW.md`](docs/VMC_ARCHITECTURE_OVERVIEW.md) for
the full design and [`docs/VMC_DEVELOPMENT_PROMPT.txt`](docs/VMC_DEVELOPMENT_PROMPT.txt)
for the build plan.

## Status: Phase 1 (Foundation) — in progress

Done:
- `models.py` — the full `ExposureContext` Pydantic tree from architecture §6
- Provider-agnostic AI layer (`src/vmc/providers/`):
  - `LLMProvider` protocol + `ToolSpec` (`base.py`)
  - `ProviderError` taxonomy (`errors.py`)
  - Shared schema-repair retry contract, one retry with the validation error
    appended to the prompt (`repair.py`)
  - Shared back-off + fallback-chain contract: exponential back-off
    (1s/2s/4s) on transient errors, immediate fallthrough on
    auth/context-too-long, required-agent abort vs optional-agent graceful
    degrade (`retry.py`)
  - `GeminiProvider` and `GroqProvider` concrete adapters (`gemini_provider.py`,
    `groq_provider.py`) — both lazy-import their SDK so the package installs
    and tests run without either dependency present
  - `FakeProvider` for deterministic offline tests (`fake_provider.py`)
  - `ModelRouter` reading `config/model_router.yaml`, agent →
    {provider, model, temperature} + `fallback_chain` (`router.py`)
- Agent 1 — Ingestion & Normalization (`src/vmc/agents/ingest.py`):
  - Alias-based CSV column mapping (covers Qualys/Nessus/Rapid7-style header
    names plus a generic scanner-agnostic set) with basic scanner
    auto-detection
  - `architecture.md` → `NetworkGraph` parser (zone table + trust-edge
    bullet list)
  - Finding → `Asset`/`TeamInfo` mapping with `DataQualityIssue` emission for
    unparseable rows, ambiguous ownership, and orphaned zone references
  - `python -m vmc.cli ingest <findings.csv> <architecture.md>` — the Phase 1
    CLI deliverable

Not started yet: Agent 2's segmentation scoring + vision cross-check,
Agents 3-9, orchestrator DAG, persistence, API, frontend.

## ⚠️ Sample data gap

`docs/VMC_DEVELOPMENT_PROMPT.txt` and `ghrab_risk_methodology.md` (repo root)
describe a `ghrab_vulnerabilities.csv` / `ghrab_architecture.md` /
`ghrab-architecture.png` test dataset (32-33 findings: Zerologon, Log4Shell,
the VLAN 10↔40 flat-trust misconfig, etc.) that's meant to be the integration
test and sanity-check ground truth for the whole pipeline. **Those files do
not exist anywhere in this repo** — only prose describing them does. Drop the
real files into `docs/sample_data/` before relying on Agent 1 (or any later
agent) against the actual Ghrab scenario.

In the meantime, Agent 1's tests run against small synthetic fixtures in
`tests/fixtures/` (`sample_findings.csv`, `sample_architecture.md`) that
exercise the parser logic — column-alias mapping, scanner detection, the
zone-table + trust-edge markdown parser, and all three `DataQualityIssue`
types — but are **not** the Ghrab dataset and prove nothing about the real
scenario's expected rankings (see `ghrab_risk_methodology.md` §9 for those
sanity checks once Agent 5 exists).

The `architecture.md` parser in particular (`parse_architecture_markdown` in
`ingest.py`) targets an inferred `| VLAN | Zone | Team | Compliance |`
table + `Source -> Target: description` trust-edge convention — re-check it
against the real `ghrab_architecture.md`'s actual structure once supplied;
it's the part of Agent 1 most likely to need adjustment.

## Setup

```bash
cd vmc-platform
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"        # core + test deps
.venv/bin/pip install -e ".[gemini,groq]" # optional, only needed for live LLM calls
```

## Run tests

```bash
.venv/bin/python -m pytest -q
```

## Run Agent 1 against a CSV + architecture doc

```bash
.venv/bin/python -m vmc.cli ingest <findings.csv> <architecture.md>
```

## Layout

```
src/vmc/
  models.py           # ExposureContext + every Pydantic type in it
  providers/           # LLMProvider protocol, adapters, ModelRouter, retry/repair contract
  agents/               # Agent 1 today; agents 2-9 land here as they're built
  orchestrator/         # DAG runner (not yet implemented)
  api/                   # FastAPI app (not yet implemented)
config/
  model_router.yaml     # ModelRouter policy — agent -> {provider, model, temperature}, fallback_chain
docs/
  sample_data/           # put ghrab_vulnerabilities.csv / ghrab_architecture.md / ghrab-architecture.png here
tests/
  fixtures/              # synthetic (non-Ghrab) fixtures for unit-testing Agent 1's parsers
frontend/                # React dashboard (Phase 3, not started)
```
