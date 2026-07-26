# VOC Agents & API Breakdown

This document maps every agent in the system, what it does, and which APIs it calls.

## Architecture summary

- All agents live in `backend/agents/` and share a common base (`backend/agents/base.py`).
- LLM calls go through a single abstraction layer, `backend/core/providers.py`, built on **litellm** (`litellm.completion`) — no agent calls a provider SDK directly.
- Each agent is assigned a "role" (e.g. `attack_path`, `correlation`, `triage`, `compliance`, `remediation`) with a default provider in `backend/core/config.py`, and a fallback chain (`mistral → groq → gemini → anthropic → openai → deepseek → xai`) if the default fails.
- **Client-side rate limiting** (`backend/core/providers.py`): to avoid tripping free-tier request-per-minute caps, calls to the same provider are spaced by a minimum interval, and a `429` triggers a bounded retry-with-backoff on that provider (honoring `Retry-After`) *before* falling through the chain. All tunable via env — no code change needed:
  - `LLM_MIN_INTERVAL_SEC` (default `4.0`) — global min seconds between same-provider calls; per-provider overrides `LLM_MIN_INTERVAL_GROQ` (2.5), `LLM_MIN_INTERVAL_GEMINI` (4.5), `LLM_MIN_INTERVAL_MISTRAL` (1.5).
  - `LLM_MAX_RETRIES` (default `4`), `LLM_BACKOFF_BASE_SEC` (default `5.0`), `LLM_BACKOFF_MAX_SEC` (default `60.0`).
  - `LLM_REQUEST_TIMEOUT_SEC` (default `60.0`) — hard per-attempt wall-clock cap handed to the HTTP client so a hung provider can't stall a run; a timeout is treated as retryable (same-provider retry with backoff, then fallback), exactly like a `429`. Set `0` to disable the client timeout. (Phase 5.)
  - Raise the intervals if you still hit limits; set `LLM_MIN_INTERVAL_SEC=0` to disable throttling entirely (e.g. on a paid tier).
  - **Per-model** spacing (`MODEL_MIN_INTERVAL`) keys the throttle on `(provider, model)` because free-tier RPS caps are per-model — e.g. `mistral-small-2506` allows ~5 RPS but `mistral-medium-2505` ~0.42 RPS (2.75s spacing). See `core/config.py`.
- **Inbound API rate limiting** (`backend/core/ratelimit.py`): the platform has **no authentication layer** — anyone who can reach the API can call it — so `POST /api/analyze` and `POST /api/chat` (the only two endpoints that trigger real LLM spend) are additionally guarded by an in-memory, IP-keyed sliding-window limiter, checked before the SSE stream opens. This is a stopgap against a runaway client, not a real multi-tenant quota (IPs are spoofable / shared behind NAT); real auth would be needed for that. Tunable via env:
  - `RATE_LIMIT_ANALYZE_PER_HOUR` (default `6`), `RATE_LIMIT_CHAT_PER_MINUTE` (default `10`).
  - Exceeding the limit returns `429` with a JSON body (`message`, `retry_after` seconds) instead of a silent failure or a mid-stream error.
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

> **Note (post-brief):** the per-role model/provider defaults above are historical. The current deployment runs **Mistral only** (free tier) with per-role models tuned to each model's free-tier throughput — see `DEFAULT_AGENT_MODEL` in `core/config.py` (`capability`/`remediation`/`compliance` → `mistral-small-2506`; `attack_path`/`correlation`/`triage` → `mistral-medium-2505`). The provider abstraction is unchanged and still vendor-agnostic.

---

## Attack-Path Detection Intelligence (Phases 0–5)

The detection subsystem was upgraded from a regex-classifier + hardcoded-graph engine into a tool-using, graph-grounded, eval-measured, production-hardened detector. It rediscovers attack paths from CMDB grounding alone — the documented oracle is **never** fed to any classifier, graph, or agent; it exists only to score detection quality. Architecture stays **deterministic-first, AI-additive**: with no provider connected, the deterministic engine produces exactly what it did before, and every AI layer degrades cleanly.

### Pipeline (`agents/orchestrator.py`)

Two explicit halves:

- **`compute_deterministic()`** — always runs, token-free, no DB, no key. Ingest + GRS scoring → CMDB parse → regex capability classification (`core/capability.classify_all`) → reachability graph + path discovery (`core/attack_graph.discover_paths`) → held-out oracle load (`core/graph.build_chains`, scoring-only).
- **`run_ai_layer()`** — spends tokens, mutates the result in place, polls `should_cancel()` at every agent boundary. Order: **Capability Extractor** (hybrid re-classify → rebuild graph if enriched) → **Analyst Detection Agent** → Discovery → Correlation → Compliance → Triage. Each agent is wrapped so a provider failure preserves the deterministic layer.

### Capability Extractor — hybrid classifier (Phase 1)

`core/capability.classify_all_hybrid` + `core/capability_llm.py`. Regex pass (fast, free, deterministic) merged with an LLM pass that reads each finding's full Title/Description/Consequence/CVSS/CVE and returns structured effects/grants/precondition/is_entry. The LLM **never names hosts or zones** — host-pivots stay derived deterministically in the merge, so it cannot introduce an out-of-scope host/QID (hallucination is 0 by construction). Output is Pydantic-validated + vocab-filtered (`LLMCapability.sanitized()`); malformed items are dropped. Cached under `data/cache/capability/` keyed by a hash of finding content + model id, at temperature 0 → re-runs are token-free and reproducible. `CAPABILITY_LLM_ENABLED=0` (or no provider) ⇒ regex-only, byte-identical to pre-Phase-1.

### Environment-agnostic graph (Phase 2)

`core/attack_graph.py` derives crown jewels, entry points, and tier adjacency from CMDB **trust levels, criticality, platform strings, and §4 dependency edges** — not literal VLAN numbers. All tokens/thresholds are config-driven (`core/config.py`: `ZONE_*_TRUST_TOKENS`, `CROWN_CRITICALITY_TOKENS`, `AD_PLATFORM_TOKENS`, `CROWN_ACW_THRESHOLD`). The deterministic ranker's weights are also config-driven (`DISC_SCORE_*`).

### Analyst Detection Agent + tool contract (Phase 3)

`agents/analyst_agent.detect_attack_paths` drives a **bounded ReAct loop** (`agents/agent_loop.run_react_loop`) over read-only tools backed by the real graph + CMDB (`agents/detection_tools.py`):

| Tool | Returns |
|---|---|
| `list_entry_points()` | internet/untrusted-reachable hosts |
| `list_crown_jewels()` | crown-jewel targets with business value |
| `neighbors(host)` | outbound edges: `to`, `kind`, enabler `qid` |
| `finding_detail(qid)` | full finding text + extracted capability |
| `test_hop(from_host, to_host)` | whether a real enabling edge exists, and which QID/relationship justifies it |
| `shortest_paths(from_host, to_host, k)` | graph-computed candidate routes |

The loop is provider-agnostic (a JSON-action protocol over plain completions, no vendor tool-calling dependency), seeded with precomputed shortest-path candidates, and **cost-bounded absolutely**: a hard iteration cap, an estimated-token budget, and a per-call token cap (`DETECTION_AGENT_MAX_ITERS` / `_TOKEN_BUDGET` / `_MAX_TOKENS`), temperature 0. Cancellation is cooperative. Tools execute locally (token-free). `DETECTION_AGENT_ENABLED=0` falls back to the pre-Phase-3 single-shot reasoning.

### Graph-backed verification & calibrated score (Phase 4)

`agents/analyst_agent._build_path` labels every reconstructed path:

- **`grounded`** — every hop is a real enabling graph edge forming a connected INTERNET→target walk (soundness 1.0 by construction).
- **`plausible`** — hosts + cited QIDs all resolve, but ≥1 hop the graph can't confirm (kept with `verified:false`, never presented as grounded).
- **`rejected`** — no anchorable real host ⇒ not emitted.

A QID-less lateral/adjacency edge may surface a cited QID only if it's a real finding on one of the two endpoint hosts; foreign QIDs are stripped.

**Calibrated score** (`_score_path`) = weighted sum of four inspectable components, each in [0,1], exposed alongside the scalar in `score_components`:

```text
score = ( W_reach·reachability + W_exploit·exploitability
        + W_business·business_value + W_chain·chain_length ) × damping
  reachability   = verified-hop ratio (real edges / total hops)
  exploitability = strongest signal across cited findings: KEV > EPSS > CVSS
                   when present, else GRS/ACW (in-dataset only, no external feeds)
  business_value = target crown-jewel value (zone criticality + DORA_CIF + exposure)
  chain_length   = ideal_hops / max(hops, ideal_hops)   [shorter scores higher]
  damping        = PATH_PLAUSIBLE_DAMPING (<1) for plausible paths, else 1.0
```

Weights, damping, and normalisers live in `core/config.py` (`PATH_SCORE_WEIGHTS`, `PATH_PLAUSIBLE_DAMPING`, `PATH_CHAIN_IDEAL_HOPS`, `PATH_GRS_CEILING`) — nothing magic inline. Plausible paths are damped so they can never outrank an equal-component grounded path. Emitted paths are score-sorted before the `DETECTION_MAX_EMITTED_PATHS` cap.

### Production hardening (Phase 5)

- **Resilience:** per-request timeout (`LLM_REQUEST_TIMEOUT_SEC`) wired into `litellm.completion`, timeouts retried like 429s; every LLM JSON parse is brace-repair-tolerant (`call_llm_json`, `agent_loop._loads`) and structurally validated (Pydantic for capability, real-host/QID anchoring for detection) with a drop path; per-agent try/except preserves the deterministic layer end-to-end (covered by `test_no_provider_run_preserves_deterministic_layer`).
- **Determinism:** structured roles (`capability`, `correlation`, `attack_path`, `remediation`, `compliance`) sample at temperature 0 via `DEFAULT_AGENT_TEMPERATURE`; only `triage` (prose) keeps a documented non-zero temp. Model id is recorded in every cached capability artifact.
- **Observability:** `core/call_log.py` records model / provider / tokens (prompt+completion) / cost / latency / attempt per call. `call_log.marker()` + `summarize_since()` produce **real** per-run token/cost/latency accounting (by role and provider), attached as `result.run_trace` (with the detection reasoning trace + tier counts) and persisted alongside the analysis in the discovery blob (`api/state._attach_ai` splits it back out on rehydrate). The detection diag also carries a real `accounting` block (replacing the loop's len/4 `tokens_est`).
- **Config:** all thresholds/budgets/model-ids/heuristics live in `core/config.py` or env.

### Evaluation harness (Phase 0)

`backend/eval/detection.py` runs the full pipeline per dataset (ghrab, velon) against the held-out oracle and reports target-level + edge-level precision/recall/F1, soundness (overall and grounded-only, both must be 1.0), ranking (AP / MRR), and hallucination rate (must be 0).

```bash
cd backend
python -m eval.detection            # AI-on live run (spends tokens)
python -m eval.detection --no-ai    # deterministic gate (regex, no key) — reproducible
python -m eval.detection --no-ai --update-baseline   # recommit the deterministic baseline
python -m eval.detection --json     # machine-readable
python -m pytest -q                 # 46 tests incl. regression gate + no-oracle-leakage
```

Committed baselines under `eval/baselines/` are **deterministic-only** (regex, no key) so the regression gate (`eval/test_detection_regression.py`, AI-off) is fast and never flakes on a provider rate limit. The AI-on run's edge-QID-Jaccard wobbles slightly vs the deterministic baseline (hybrid-caps + un-cached detection-loop nondeterminism); the hard invariants — soundness 1.0, grounded-soundness 1.0, hallucination 0 — hold on every run. **Do not re-commit the baseline from an AI-on run.**
