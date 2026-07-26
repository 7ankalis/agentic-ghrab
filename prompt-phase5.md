# Continue: Attack-Path Detection Intelligence upgrade — PHASE 5 (VOC backend)

You're taking over a phased implementation of `docs/attack-path-intelligence-brief.md`
in this repo. Read that brief first (esp. Phase 5, the final phase). Work carefully —
this is the "production hardening" pass, not a feature phase. After finishing, run the
eval harness + full pytest, report the metric delta, and PAUSE for my confirmation.
Branch is `rework`. DO NOT commit or push unless I tell you.

## Environment / conventions (important gotchas)
- Repo: /home/salamnki/Documents/voc . `backend/` is the sys.path root — imports are
  `from core...`, `from agents...` (NOT `backend.core`). Run things from `backend/`.
- The Bash working dir RESETS to repo root between calls. Either `cd /…/voc/backend &&`
  each call, or run modules by file path (the eval harness self-bootstraps sys.path).
- Provider: Mistral only (free tier), key in `backend/.env`, live now. Be frugal
  (free-tier RPS). Per-MODEL throttling is implemented (config.MODEL_MIN_INTERVAL).
- Per-role models (config.DEFAULT_AGENT_MODEL): capability→mistral-small-2506 (5 RPS),
  attack_path/correlation/triage→mistral-medium-2505 (0.42 RPS = 2.75s spacing),
  remediation/compliance→small-2506. AVOID mistral-large/magistral (0.03–0.08 RPS).
- Each live eval run spends ~15 medium-model calls (2 datasets). The capability LLM
  pass is content-hash cached; the detection ReAct loop is NOT cached (fresh each run).
- Working tree currently has uncommitted changes across Phases 1–4 (agents/, core/,
  eval/, plus a WIP `data/elihowa_*` fixture and a small frontend diff in
  reportBuilders.ts) — nothing has been committed yet on this branch. Don't assume a
  clean tree; check `git status`/`git diff` yourself before reasoning about "what
  changed."

## Non-negotiable invariants (from the brief — breaking any fails the task)
1. NEVER feed the oracle (data/oracle/, core/oracle.py, core/graph.build_chains,
   Attack_Path_Ref) to any classifier/graph/agent/tool. Oracle = scoring only.
   Enforced by eval/test_no_oracle_leakage.py + a tool-leakage test.
2. No fabrication: every hop traces to a real asset + real QID + a real enabling
   graph edge. Hallucination rate MUST stay 0.
3. Graceful degradation: no provider ⇒ deterministic engine identical to today
   (regex-only). compute_deterministic stays token-free and instant.
4. Provider-agnostic with fallback; bounded token/iteration budgets; cooperative
   cancellation (should_cancel) preserved.

## What's DONE (Phases 0–4, all validated: `cd backend && python -m pytest -q` = 36 green)

Phase 0 — eval harness `backend/eval/` (detection.py): runs pipeline per dataset
(ghrab, velon) vs held-out oracle; target-level + edge-level precision/recall/F1,
soundness (split by origin: deterministic vs ai), hallucination. Run:
`cd backend && python -m eval.detection [--no-ai] [--update-baseline] [--json]`.
Committed baselines under eval/baselines/ are DETERMINISTIC-ONLY (regex, no key).
The regression test (test_detection_regression.py) runs AI-OFF and gates
target recall/F1, edge QID-Jaccard/recall, soundness (≥ baseline−0.02), halluc (=0).

Phase 1 — hybrid regex+LLM capability classifier (core/capability_llm.py,
core/capability.classify_all_hybrid). LLM classifies effects/grants/entry only;
host-pivots stay DERIVED deterministically (halluc structurally 0). Batched, cached,
temp 0. On by default (CAPABILITY_LLM_ENABLED).

Phase 2 — environment-agnostic graph (core/attack_graph.py). Removed hardcoded
DOMAIN_VLANS/CROWN_VLANS/tier constants; crown/entry/pivots derived from CMDB trust
levels, criticality, §4 dependency_edges. Config-driven tokens in core/config.py.

Phase 3 — tool-using iterative detection agent: agents/agent_loop.py (bounded
ReAct engine over agents/detection_tools.py's read-only graph+CMDB tools:
list_entry_points, list_crown_jewels, neighbors, finding_detail, test_hop,
shortest_paths). agents/analyst_agent.detect_attack_paths drives the loop;
DETECTION_AGENT_ENABLED=0 falls back to the pre-Phase-3 single-shot reasoning.

Phase 4 — graph-backed verification & calibrated confidence (JUST FINISHED):
- `agents/analyst_agent.py` `_build_path` (replaces the old `_verify_path`):
  labels every reconstructed path `grounded` (every hop a real edge, connected
  INTERNET→target walk), `plausible` (hosts+QIDs resolve, ≥1 hop the graph can't
  confirm — hop kept with `verified:false`, kind:"unverified"), or `rejected`
  (no anchorable real host — not emitted). Tightened the cited-QID rule: a
  QID-less lateral edge may only surface a cited QID if it's a real finding on
  an endpoint host (`_endpoint_qids`); foreign QIDs are stripped to None.
- Calibrated score `_score_path`: weighted sum of 4 exposed components
  (reachability=verified-hop ratio, exploitability=`_exploit_signal` [KEV>EPSS>
  CVSS if present else GRS/ACW], business_value=target_value, chain_length=
  ideal/actual hops). Weights + damping + ceilings in core/config.py's new
  "Phase 4" block: PATH_SCORE_WEIGHTS, PATH_PLAUSIBLE_DAMPING (0.6),
  PATH_CHAIN_IDEAL_HOPS (2), PATH_GRS_CEILING (100.0). Plausible paths are
  damped so they can never outrank an equal-component grounded path.
  `detect_attack_paths` output paths are score-sorted before the
  `_MAX_EMITTED_PATHS` cap; diag now includes `tier_counts` {grounded,
  plausible, rejected} and `rejected` (renamed concept, `dropped_unverified`
  kept as an alias for the same count).
- Per-path additive schema fields: `label`, `score`, `score_components` (dict
  with the 4 components + `weights`, `plausible_damping`, `raw`). `grounded`
  bool is now `label == "grounded"`.
- `eval/detection.py`: PathView gained `label`/`score`; new `_soundness_grounded`
  (soundness restricted to label=="grounded", must be 1.0) and `_ranking_metrics`
  (average_precision/MRR/precision@N over "detected target is oracle-documented",
  scores min-max normalized per-origin before ranking). Wired into
  `evaluate_dataset` as `soundness_grounded` / `ranking`. `render_table` uses a
  new `_safe_dig` so older baselines missing Phase-4 keys don't crash printing.
- `eval/test_detection_agent.py`: 5 new tests (plausible-not-grounded labeling,
  grounded-subset soundness==1.0, lateral-hop foreign-QID stripping vs
  endpoint-QID retention, score ranking/damping monotonicity + component
  exposure, unresolvable-host → rejected/not-emitted) + 1 ranking-metric unit
  test. 31 → 36 tests green.

Detected-path output schema (round-trips through discovery["ai_detected"], frontend
contract preserved — additive only): per path {name, entry, target, hops:[{from, to,
via_qid, enabler, why, kind, verified}], business_impact, confidence, label, grounded,
verified_hops, total_hops, score, score_components}; plus diag {reasoning_trace,
stopped_reason, iterations, tokens_est, tier_counts, rejected, dropped_unverified}.

## Current metrics (from the Phase 4 run just completed)
Committed baseline (DETERMINISTIC/regex, unchanged since Phase 0): ghrab target
recall 0.667 (misses FILESRV01, DB-CRM01), edge QID-Jaccard 0.423, edge recall
0.503; velon target recall 0.833 (misses FILESRV01), edge QID-Jaccard 0.480, edge
recall 0.536. Both soundness 1.0, hallucination 0.

AI-off gate (`python -m eval.detection --no-ai`): byte-identical to baseline on
every committed metric (all deltas `(=)`) — Phase 4 touched nothing in the
deterministic path. New metrics reported alongside: soundness(grounded)=1.000
both datasets, ranking MRR=1.000 both, ranking AP 0.732 (ghrab) / 0.708 (velon).

AI-on live run: soundness=1.000, soundness(grounded)=1.000, hallucination=0.000
on both datasets (unchanged from Phase 3). ranking MRR=1.000 both (the
top-ranked detected target is always oracle-documented). ranking AP 0.649
(ghrab) / 0.678 (velon). Edge metrics moved slightly (mostly up) same as Phase 3.
NOTE: `python -m eval.detection` (AI-on) prints one "regression" — velon edge
QID-Jaccard 0.480→0.451. This is a PRE-EXISTING Phase-1 hybrid-caps effect on the
DETERMINISTIC paths, reverified this session to reproduce at exactly 0.451 with
ZERO AI-agent paths added (LLM-hybrid caps + deterministic-only pathfinding).
The gate test runs AI-OFF (regex) and is green. Do NOT re-commit the baseline;
it stays regex/reproducible.

## Open decisions (already made, don't re-litigate)
- Exploit feeds: in-dataset GRS/ACW/CVSS/EPSS/KEV only, NO external network feeds.
- Model: Mistral (attack_path→mistral-medium-2505). Schema changes: additive-only OK.

## NEXT: Phase 5 — production hardening
From the brief, verbatim goal: "extremely production-ready." Concretely:
- **Observability**: structured logging per agent (model, tokens in/out, latency,
  tool calls, cache hits); a per-run trace object persisted alongside the
  analysis; token/cost accounting surfaced in the run record. Look at how
  agents/agent_loop.py's `loop.trace`/`tokens_est` and agents/base.py's
  call_llm/ask_json already expose model/provider — extend, don't replace.
- **Resilience**: timeouts + bounded retries with backoff on provider calls
  (core/providers.py already has LLM_MAX_RETRIES/LLM_BACKOFF_* — check whether
  timeouts are actually wired into the HTTP client, not just retry counts);
  every LLM JSON parse guarded by schema validation with a repair-or-drop path;
  partial results preserved on failure (never lose the deterministic layer —
  this is largely already true via the try/except-per-agent pattern in
  orchestrator.py, verify it holds end-to-end).
- **Determinism/reproducibility**: temperature 0 (or documented) for
  classification/detection (already true for capability_llm and the detection
  agent — audit remediation/compliance/triage too); content-hash caching so
  identical inputs give identical outputs; model id recorded in every
  cached/persisted artifact.
- **Config**: all thresholds, budgets, model ids, and heuristics in
  core/config.py (or env) — audit for anything still magic-inline, especially
  in agents/analyst_agent.py, agents/discovery_agent.py, core/attack_graph.py's
  `_score` function (line ~431, separate from the new Phase 4 path score —
  check if it should also move its weights to config).
- **Performance**: classify findings in parallel within a bounded worker pool;
  cache aggressively; keep `compute_deterministic` token-free and instant
  (verify this is still true — Phase 1–4 all touched this path).
- **Docs**: update `docs/AGENTS.md` (create if absent) and any architecture
  note with the new pipeline, the tool contract (agents/detection_tools.py),
  the Phase 4 scoring formula, and how to run the eval harness. Update
  relevant memory/CLAUDE notes if present (check
  /home/salamnki/.claude/projects/-home-salamnki-Documents-voc/memory/ for an
  existing "attack-path-intelligence-brief" memory entry to update, not
  duplicate).

## Testing & Definition of Done (from the brief, Phase 5 is the last checkpoint)
- `pytest` green, including all existing Phase 0–4 tests plus a graceful-
  degradation test (provider disabled → deterministic output byte-identical to
  pre-change) if one doesn't already fully cover the Phase 5 resilience changes.
- Eval metrics reported for both datasets: full before/after comparison table
  vs the Phase 0 baseline (you have the Phase 4 numbers above as "before").
- No regression in existing API responses/schema consumed by the frontend;
  note there's already a small uncommitted frontend diff in
  frontend/src/lib/reportBuilders.ts from earlier work — check what it does
  before assuming it's unrelated to this task.
- A concise `CHANGES.md` (or PR description) summarizing what changed across
  ALL phases (0–5), the final metrics, and any decisions/tradeoffs — this is
  the wrap-up deliverable since Phase 5 is the last phase in the brief.

## Ways of working
- This is the LAST phase — after it's done and tests/eval are green, the brief
  is complete. Don't start inventing a "Phase 6"; if you think something's
  missing, ask rather than scope-creep.
- Prefer extending existing modules over rewrites; match the surrounding code
  style, comment density, and the existing "deterministic-first, AI-additive"
  architecture established in Phases 0–4.
- If a change needs a new heavy dependency or an external network/data source,
  stop and ask first with the tradeoff.
- Keep commits small and labeled by phase. Do not commit or push unless asked.
- If anything in the real code contradicts this brief or this handoff (file
  moved, a Phase 1–4 detail is stale), trust the code, say so, and adapt.

Start by confirming state (`cd backend && python -m pytest -q` should show 36
passed) and skimming the Phase 4 files named above (agents/analyst_agent.py's
`_build_path`/`_score_path`, eval/detection.py's `_soundness_grounded`/
`_ranking_metrics`, core/config.py's Phase 4 block), then give me a short
Phase 5 plan and WAIT for my go-ahead before editing.
