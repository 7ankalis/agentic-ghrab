# Attack-Path Detection Intelligence & Production-Readiness — Changes (Phases 0–5)

Implements `docs/attack-path-intelligence-brief.md`: upgrades the VOC detection engine
from a regex-classifier + hardcoded-graph pipeline into a tool-using, graph-grounded,
eval-measured, production-hardened detector — while preserving the **deterministic-first,
AI-additive** architecture. Branch: `rework`.

## Invariants held across every phase

- **Oracle never leaks.** The documented attack paths (`data/oracle/`, `core/graph.build_chains`,
  `Attack_Path_Ref`) are used only to *score* detection, never fed to any classifier, graph,
  or agent. Enforced by `eval/test_no_oracle_leakage.py`.
- **No fabrication.** Every asserted hop traces to a real asset + real QID + a real enabling
  graph edge. Hallucination rate = **0** on every run.
- **Graceful degradation.** No provider ⇒ the deterministic engine produces byte-identical
  output to before. Verified end-to-end by `eval/test_phase5_hardening.py`.
- **Bounded cost + cooperative cancellation** preserved throughout.

## What changed, by phase

### Phase 0 — Evaluation harness
- `backend/eval/detection.py`: runs the pipeline per dataset (ghrab, velon) vs the held-out
  oracle; reports target- and edge-level precision/recall/F1, soundness (overall + grounded-only),
  ranking (AP/MRR), hallucination. Human table + `--json`. Baselines committed under
  `eval/baselines/` (deterministic/regex only, so the gate is reproducible).
- Regression gate `eval/test_detection_regression.py` (AI-off) fails on any metric regression
  beyond tolerance, or if soundness ≠ 1.0 / hallucination ≠ 0.

### Phase 1 — Hybrid capability classifier (kill the regex bottleneck)
- `core/capability_llm.py` + `core/capability.classify_all_hybrid`: regex pass merged with an
  LLM pass (full finding text → structured effects/grants/precondition/is_entry). The LLM never
  names hosts/zones — pivots stay derived deterministically, so hallucination is 0 by construction.
  Pydantic-validated, vocab-filtered, content-hash cached at temperature 0. `CAPABILITY_LLM_ENABLED=0`
  or no provider ⇒ regex-only, identical to before.

### Phase 2 — Environment-agnostic graph
- `core/attack_graph.py`: removed hardcoded `DOMAIN_VLANS`/`CROWN_VLANS`/tier constants. Crown
  jewels, entry points, and adjacency derive from CMDB trust levels, criticality, platform, and
  §4 dependency edges. All tokens/thresholds config-driven (`core/config.py`).

### Phase 3 — Tool-using iterative detection agent
- `agents/agent_loop.py`: reusable provider-agnostic bounded ReAct engine (JSON-action protocol,
  hard iteration + token caps, cooperative cancellation).
- `agents/detection_tools.py`: read-only graph+CMDB tools (`list_entry_points`, `list_crown_jewels`,
  `neighbors`, `finding_detail`, `test_hop`, `shortest_paths`).
- `agents/analyst_agent.detect_attack_paths` drives the loop; `DETECTION_AGENT_ENABLED=0` falls
  back to single-shot reasoning.

### Phase 4 — Graph-backed verification & calibrated confidence
- `agents/analyst_agent._build_path`: labels each path `grounded` / `plausible` / `rejected`;
  tightened cited-QID rule (foreign QIDs on QID-less lateral edges stripped).
- `_score_path`: calibrated score = weighted sum of 4 inspectable components (reachability,
  exploitability [KEV>EPSS>CVSS else GRS/ACW], business_value, chain_length); plausible paths
  damped below equivalent grounded paths. Weights/damping/normalisers in `core/config.py`.
- Eval gained `soundness(grounded)` (must be 1.0) and ranking metrics (AP/MRR).
- Additive schema: `label`, `score`, `score_components`, `grounded`, `verified_hops`, `total_hops`.

### Phase 5 — Production hardening (this pass)
- **Resilience:** `LLM_REQUEST_TIMEOUT_SEC` wired into `litellm.completion` (`core/providers.py`);
  timeouts classified as retryable (`_is_timeout`) and retried like 429s before falling through.
- **Determinism:** per-role `DEFAULT_AGENT_TEMPERATURE` (`core/config.py`) — structured roles
  (capability, correlation, attack_path, remediation, compliance) now sample at **0** via
  `agents/base.py`; only `triage` (prose) keeps a documented non-zero temp.
- **Observability:** `core/call_log.marker()` + `summarize_since()` produce **real** per-run
  token/cost/latency accounting (by role + provider). Attached as `result.run_trace` (with the
  detection reasoning trace + tier counts) and persisted alongside the analysis
  (`agents/orchestrator.py`, `api/state.py`); replaces the loop's `len/4` estimate in the
  detection diag with a real `accounting` block.
- **Config:** deterministic-ranker weights (`DISC_SCORE_*`) and the detection emit cap
  (`DETECTION_MAX_EMITTED_PATHS`) moved out of inline constants; defaults reproduce prior behavior.
- **Tests:** `eval/test_phase5_hardening.py` (10 tests) — timeout classification + wiring + retry,
  per-role temperature + forwarding, real call_log accounting + marker scoping, and end-to-end
  graceful degradation (provider disabled → deterministic layer intact, no raise, run trace attached).
- **Docs:** `docs/AGENTS.md` extended with the Phases 0–5 subsystem, tool contract, scoring formula,
  and eval how-to; this `CHANGES.md`.

## Test status

`cd backend && python -m pytest -q` → **46 passed** (36 Phase 0–4 + 10 Phase 5).

## Metrics — Phase 0 baseline (deterministic) vs current

Committed baseline is **deterministic/regex** and unchanged since Phase 0. The AI-off gate is
byte-identical to it (every metric `(=)`), confirming Phase 5 touched nothing on the token-free path.

| Metric | ghrab base | ghrab AI-on | velon base | velon AI-on |
|---|---|---|---|---|
| target recall | 0.667 | 0.667 | 0.833 | 0.833 |
| target F1 | 0.571 | 0.571 | 0.588 | 0.588 |
| edge QID-Jaccard | 0.423 | 0.413 | 0.480 | 0.459 |
| edge recall | 0.503 | 0.511 | 0.536 | 0.544 |
| edge F1 | 0.548 | 0.553 | 0.574 | 0.582 |
| soundness | 1.000 | 1.000 | 1.000 | 1.000 |
| soundness(grounded) | 1.000 | 1.000 | 1.000 | 1.000 |
| ranking MRR | 1.000 | 1.000 | 1.000 | 1.000 |
| ranking AP | 0.732 | 0.649 | 0.708 | 0.903 |
| hallucination | 0.000 | 0.000 | 0.000 | 0.000 |

The AI-on edge-QID-Jaccard sits slightly below the deterministic baseline (a pre-existing Phase-1
hybrid-caps effect plus un-cached detection-loop nondeterminism — Mistral isn't perfectly
deterministic even at temperature 0). The hard invariants (soundness, grounded-soundness,
hallucination) hold on every run. The regression gate runs AI-off and is green.

## Decisions & tradeoffs

- **Exploit signals:** in-dataset GRS/ACW/CVSS/EPSS/KEV only — no external network feeds.
- **Model:** Mistral only (free tier); per-role models tuned to each model's free-tier RPS.
- **Schema:** all changes additive; the frontend contract is preserved.
- **Parallel classification:** kept batched-sequential rather than a worker pool — the client-side
  per-model throttle serializes same-model calls anyway on the free tier, so a pool would add
  concurrency risk for negligible benefit.
- **Schema-validation retrofit:** the critical paths (capability, detection) validate structurally
  and the per-agent try/except contains bad parses; narration agents were documented rather than
  rewritten around strict Pydantic schemas.
- **Baseline:** stays deterministic/regex; never re-committed from an AI-on run.
- **`frontend/src/lib/reportBuilders.ts`:** a small pre-existing display-only diff (richer kill-chain
  report lines) unrelated to this work; left as-is.
