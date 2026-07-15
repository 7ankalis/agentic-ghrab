# VOC Agents & API Breakdown

This document maps every agent in the system, what it does, and which APIs it calls.

## Architecture summary

- All agents live in `backend/agents/` and share a common base (`backend/agents/base.py`).
- LLM calls go through a single abstraction layer, `backend/core/providers.py`, built on **litellm** (`litellm.completion`) — no agent calls a provider SDK directly.
- Each agent is assigned a "role" (e.g. `attack_path`, `correlation`, `triage`, `compliance`, `remediation`) with a default provider in `backend/core/config.py`, and a fallback chain (`mistral → groq → gemini → anthropic → openai → deepseek → xai`) if the default fails.
- **Client-side rate limiting** (`backend/core/providers.py`): to avoid tripping free-tier request-per-minute caps, calls to the same provider are spaced by a minimum interval, and a `429` triggers a bounded retry-with-backoff on that provider (honoring `Retry-After`) *before* falling through the chain. All tunable via env — no code change needed:
  - `LLM_MIN_INTERVAL_SEC` (default `4.0`) — global min seconds between same-provider calls; per-provider overrides `LLM_MIN_INTERVAL_GROQ` (2.5), `LLM_MIN_INTERVAL_GEMINI` (4.5), `LLM_MIN_INTERVAL_MISTRAL` (1.5).
  - `LLM_MAX_RETRIES` (default `4`), `LLM_BACKOFF_BASE_SEC` (default `5.0`), `LLM_BACKOFF_MAX_SEC` (default `60.0`).
  - Raise the intervals if you still hit limits; set `LLM_MIN_INTERVAL_SEC=0` to disable throttling entirely (e.g. on a paid tier).
- No scanning/threat-intel APIs are used anywhere (no Shodan, VirusTotal, NVD, Censys, Nmap wrapper, or raw HTTP calls found). All vulnerability/asset data is static and local: `backend/data/ghrab_vulnerabilities.csv`, `ghrab_architecture.md`, and CMDB parsing in `core/cmdb.py`.
- The deterministic risk/graph engine (`core/risk_engine.py`, `core/attack_graph.py`, `core/capability.py`, `core/graph.py`) needs no network access or API key — it computes candidate attack chains from local data. Only the AI-enrichment agents below need an LLM provider configured.

## Agents

### 1. Discovery Agent
`backend/agents/discovery_agent.py::analyze()`

Takes deterministically-enumerated candidate attack chains (from `core/attack_graph.py`) and, per chain, produces an analyst narrative (headline, narrative, business impact, choke point, confidence, novelty). Separately reasons across all paths to surface cross-path "toxic combinations" and an executive summary. Never invents hosts/CVEs — only explains ground-truth chains it's handed.

- **LLM call:** Yes — `ask_json("attack_path", ...)` for narration, `ask_json("correlation", ...)` for toxic combos.
- **Default provider:** Mistral (`mistral-large-latest`) for narration; Groq (`llama-3.3-70b-versatile`) for correlation.
- **Other external APIs:** None.

### 2. Correlation Agent
`backend/agents/correlation_agent.py::find_toxic_combinations()`

Cross-references the full findings CSV against the CMDB to surface toxic combinations not already captured in a documented `Attack_Path_Ref` chain, identifies top-risk teams, and flags mis-prioritized findings.

- **LLM call:** Yes — `ask_json("correlation", ...)`.
- **Default provider:** Groq (`llama-3.3-70b-versatile`).
- **Other external APIs:** None.

### 3. Triage / Analyst Agent
`backend/agents/triage_agent.py` (`answer_question()`, `executive_synthesis()`)

Powers the AI Analyst chat tab (grounded Q&A over CMDB + findings + discovered attack paths) and the one-paragraph executive synthesis on the Overview tab.

- **LLM call:** Yes — `ask("triage", ...)` (plain text, not JSON mode).
- **Default provider:** Mistral (`mistral-large-latest`).
- **Other external APIs:** None.

### 4. Attack Path Agent
`backend/agents/attack_path_agent.py::narrate_chain()`

Turns a single deterministic chain (from `core/graph.py`'s `Chain`) into an analyst narrative: headline, step-by-step narrative, business impact, primary choke point, and owning teams. Distinct from Discovery Agent, which does bulk narration of *all* candidate chains plus cross-path reasoning — this one narrates a single already-built chain. The step sequence itself is ground truth and is never invented.

- **LLM call:** Yes — `ask_json("attack_path", ...)`.
- **Default provider:** Mistral (`mistral-large-latest`).
- **Other external APIs:** None.

### 5. Compliance Agent
`backend/agents/compliance_agent.py::compliance_summary()`

Reasons over the `Compliance_Ref` column plus CMDB CDE/SWIFT scope and DORA CIF (critical/important function) facts to produce a compliance posture briefing: frameworks in scope, key gaps, DORA SLA overlay note, executive summary for an auditor/board. References PCI DSS / SWIFT CSP / EU DORA / CIS purely as data labels from the CSV/CMDB — no live compliance API lookups.

- **LLM call:** Yes — `ask_json("compliance", ...)`.
- **Default provider:** Mistral (`mistral-large-latest`).
- **Other external APIs:** None.

### 6. Remediation Agent
`backend/agents/remediation_agent.py::enrich_remediation()`

Called on-demand per finding (not part of the bulk pipeline) to enrich scanner-provided remediation text into step-by-step actions, validation steps, risk-of-fix notes, and an effort estimate.

- **LLM call:** Yes — `ask_json("remediation", ...)`.
- **Default provider:** Groq (`llama-3.3-70b-versatile`).
- **Other external APIs:** None.

### Orchestrator (not an AI agent itself)
`backend/agents/orchestrator.py::run_pipeline()`

Deterministic-first pipeline entry point that invokes the AI agents above in sequence and caches results to `backend/data/cache/analysis_cache.json`. Makes no LLM calls directly.

## LLM providers configured (via litellm)

| Provider | Env var | Default model | litellm prefix |
|---|---|---|---|
| Anthropic (Claude) | `ANTHROPIC_API_KEY` | `claude-opus-4-8` | `anthropic` |
| OpenAI (GPT) | `OPENAI_API_KEY` | `gpt-4.1` | `openai` |
| Groq | `GROQ_API_KEY` | `llama-3.3-70b-versatile` | `groq` |
| Mistral | `MISTRAL_API_KEY` | `mistral-large-latest` | `mistral` |
| Google (Gemini) | `GEMINI_API_KEY` | `gemini-2.0-flash` | `gemini` |
| DeepSeek | `DEEPSEEK_API_KEY` | `deepseek-chat` | `deepseek` |
| xAI (Grok) | `XAI_API_KEY` | `grok-4` | `xai` |

All seven keys are currently set in the root `.env`. `backend/requirements.txt` depends only on `litellm>=1.51` for LLM access (no direct `openai`/`anthropic`/`shodan` SDKs) plus `fastapi`, `uvicorn`, `pydantic`, `pandas`, `networkx`, `python-dotenv`.
