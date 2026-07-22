# Attack-Path Detection — Intelligence & Production-Readiness Brief

> Implementation brief for a Claude Code agent. Hand this off with:
> "Implement docs/attack-path-intelligence-brief.md — work phase by phase, pause after each phase for confirmation."

## Mission

You are upgrading the attack-path **detection intelligence** of this Vulnerability
Operations Center (VOC) backend from a regex-classifier + hardcoded-graph engine into a
genuinely intelligent, tool-using, graph-grounded detection system — and making the whole
thing production-ready. The bar: it should surface real attack paths a strong human analyst
would find, including non-obvious ones the current rule engine misses ("under the radar"),
while never inventing hosts, findings, or hops.

**Do not start editing yet.** Work in phases. Phase 0 is an evaluation harness — you build
the ruler before you change what it measures. Report a short plan after orientation and
after each phase.

## Orientation — read before doing anything

Read these files completely and build a mental model of the data flow. Do not summarize them
back; just internalize them.

- `backend/agents/orchestrator.py` — pipeline split: `compute_deterministic` (always) vs
  `run_ai_layer` (token-spending). This is the entry point.
- `backend/core/capability.py` — regex/keyword classification of each finding into
  ATT&CK-style capabilities. **This is the current intelligence bottleneck.**
- `backend/core/attack_graph.py` — builds the reachability graph and enumerates
  INTERNET→crown-jewel paths. Note the hardcoded constants `DOMAIN_VLANS`, `CROWN_VLANS`,
  and the VLAN `21`/`30` tier assumptions.
- `backend/core/cmdb.py` — parses the enterprise architecture doc into zones/assets/teams
  and the §2–§5 relationship grounding. `grounding_context()` is what agents see.
- `backend/agents/analyst_agent.py` — the "reason from scratch" detection agent (single-shot,
  weak hop verification: only checks host+QID exist).
- `backend/agents/discovery_agent.py` — validates/narrates the deterministic chains + toxic
  combos.
- `backend/agents/base.py`, `backend/core/providers.py`, `backend/core/config.py` — the LLM
  abstraction (`call_llm`, `call_llm_json`), persona, and active-org/dataset config.
  Understand how a provider is selected and whether tool-calling is available before
  designing Phase 3.
- `backend/core/ingestion.py` — `get_vulnerabilities()` and the finding schema (columns: QID,
  Title, Category, CVSS_Vector, CVE_ID, GRS, ACW, DORA_CIF, Hostname, VLAN_ID, Zone,
  Exposure_Tier, Description, Consequence, Responsible_Team, etc.).
- The **oracle**: locate the held-out documented attack paths (`build_chains` in
  `core/graph.py`, and any `core/oracle.py`). This is the ANSWER KEY. Confirm exactly where
  it is and how it's structured.

After reading, produce a 10-line orientation summary + the phased plan, then proceed.

## Non-negotiable invariants (breaking any of these fails the task)

1. **Never feed the oracle / documented paths / `Attack_Path_Ref` to any classifier, graph
   builder, or agent.** The whole value proposition is that the system *rediscovers* paths
   from grounding. The oracle is used ONLY to score detection quality in the eval harness and
   in the verification overlay. Add a test that asserts no oracle text reaches any agent prompt.
2. **No fabrication.** Every asserted hop must trace to (a) a real asset in the CMDB and
   (b) a real finding QID and (c) an actual enabling relationship (reachability rule /
   credential relation / dependency / capability edge). A hop that fails any of these is
   dropped or flagged unverified — never presented as grounded.
3. **Graceful degradation.** If no provider is connected, the deterministic engine must still
   produce paths exactly as today. The AI layer is additive.
4. **Provider-agnostic with a fallback.** Prefer native tool-use where the active provider
   supports it; where it doesn't, fall back to a JSON-action ReAct loop over plain
   completions. Never hard-depend on one vendor's tool-calling.
5. **Cooperative cancellation preserved** — keep the `should_cancel()`/checkpoint pattern in
   the AI layer.
6. **Cost is bounded.** Every agent has an explicit token budget and a max tool-iteration
   count. No unbounded loops.

## Phase 0 — Evaluation harness (build this FIRST, do not skip)

Goal: make "more intelligent" a number, not a vibe.

- Create `backend/eval/` with a runnable harness (`python -m backend.eval.detection` or a
  pytest) that:
  - Runs the full deterministic + AI detection pipeline against each shipped dataset
    (Ghrab, Velon).
  - Compares detected paths against the held-out oracle and computes **precision, recall,
    and F1** at two granularities: (a) reached-target level (did we find a path to each
    crown jewel the oracle documents?) and (b) hop/edge level (Jaccard overlap of enabler
    QIDs and host sequence).
  - Reports **soundness** (fraction of asserted hops that are graph-verifiable) and
    **hallucination rate** (asserted hosts/QIDs not in scope — must be 0).
  - Emits a single JSON + a human-readable table, and a baseline snapshot committed under
    `backend/eval/baselines/`.
- Add a matching pytest that fails if precision/recall/soundness regress below the committed
  baseline (with a small tolerance).

**Acceptance:** `pytest backend/eval` runs green, prints the baseline metrics for both
datasets, and the "no oracle leakage" test passes. Report the baseline numbers before Phase 1.

## Phase 1 — Intelligent capability extraction (kill the regex bottleneck)

Goal: stop losing findings to keyword gaps in `core/capability.py`.

- Introduce a **hybrid classifier**: keep the existing regex pass as a fast, free,
  deterministic baseline, and add an LLM extraction pass that reads each finding's full
  Title/Description/Consequence/CVSS/CVE and returns a structured `Capability` (effects,
  grants, preconditions, zone_transition, host_pivots, is_entry, mitre_tactic).
- Merge strategy: regex and LLM agree → high confidence; disagree or regex-empty → trust LLM
  but tag `capability_confidence` and keep the evidence span the LLM cited. Persist a
  `source` field (`regex` | `llm` | `both`).
- **Validate LLM output with a strict schema** (Pydantic model) and drop/repair anything
  malformed. Any host_pivot or zone the LLM names must resolve to a real asset/VLAN or be
  discarded.
- **Cache** classification keyed by a hash of the finding content + model id, under
  `backend/data/cache/`, so re-runs are cheap and deterministic. Respect the graceful-
  degradation rule: no provider → regex-only, identical to today.
- Add unit tests: known findings map to expected capabilities; a deliberately oddly-worded
  finding that today's regex misses is now caught by the LLM path.

**Acceptance:** eval recall improves (or holds) with hallucination still 0; classification is
cached and reproducible; regex-only mode unchanged.

## Phase 2 — Environment-agnostic graph

Goal: remove dataset-specific hardcoding so detection generalizes.

- Derive `DOMAIN_VLANS`, `CROWN_VLANS`, and the app→db tier adjacency from the CMDB grounding
  (zone trust levels, roles/platforms, criticality, DORA_CIF, and the §3/§4 reachability +
  dependency relations) instead of literal VLAN numbers. Where a heuristic is still needed,
  make it config-driven in `core/config.py`, not a constant in the graph builder.
- Crown-jewel and entry-point determination should follow the same principle: computed from
  asset criticality + zone trust + capability effects, overridable via config.
- Keep the edge-typing (entry/lateral/segmentation/credential/domain) but ensure every edge
  still carries its enabling QID/relationship for auditability.

**Acceptance:** both datasets still produce their paths with the constants removed; a
synthetic third mini-dataset (you create a tiny fixture) with different VLAN numbering also
yields correct entry→crown paths, proving generality.

## Phase 3 — Tool-using iterative detection agent (the core intelligence upgrade)

Goal: replace the single-shot `analyst_agent.py` reasoning with a bounded, multi-step,
tool-using loop that investigates like an analyst.

- Give the detection agent **tools** backed by the real graph + CMDB, e.g.:
  - `list_entry_points()`, `list_crown_jewels()`
  - `neighbors(host)` → outbound edges with enabler QID + edge kind
  - `finding_detail(qid)` → full finding text + extracted capability
  - `test_hop(from_host, to_host)` → is there a real enabling edge, and which QID/relationship
    justifies it
  - `shortest_paths(from, to, k)` → graph-computed candidate routes
- The agent runs a **bounded ReAct loop** (hard cap on iterations + tokens): hypothesize a
  path → verify each hop with `test_hop` → expand or backtrack → finalize. It must prefer
  distinct crown-jewel targets and surface non-obvious pivots (credential reuse across zones,
  hypervisor blast radius, cloud identity escalation) that the pure pathfinder ranks low or
  misses.
- **Provider-agnostic execution:** use native tool-calling when available; otherwise a
  JSON-action protocol where the model emits `{action, args}` and your loop executes and
  feeds back observations. Centralize this in a small `agents/agent_loop.py` so all agents
  can reuse it.
- Output: structured detected paths with per-hop enabler + a short "why," plus a
  `reasoning_trace` (the tool calls made) for auditability. Keep it terse and schema-validated.

**Acceptance:** on both datasets the tool-using agent recovers the oracle paths at ≥ the
deterministic engine's recall AND surfaces at least one legitimately non-obvious, fully-
verified path the deterministic ranker buries; every emitted hop passes `test_hop`;
token/iteration caps enforced; no-provider path still degrades cleanly.

## Phase 4 — Graph-backed verification & calibrated confidence

Goal: make "grounded" mean *sound*, and make confidence trustworthy.

- Replace the weak verification in the current detection agent (host-exists + QID-exists) with
  **full hop verification against the graph**: a hop is `verified` only if a real enabling
  edge exists between the two hosts and the cited QID/relationship actually enables it. A path
  is `grounded` only if every hop verifies AND it forms a connected INTERNET→target walk.
- Compute a **calibrated path score** from: reachability certainty (verified-hop ratio),
  exploitability signal (pull EPSS/KEV/CVSS if present in the data; otherwise GRS/ACW as
  today), business value (crown-jewel value, DORA_CIF), and chain length. Document the formula
  and expose the components, not just the scalar.
- Distinguish and label three states in the output: `grounded` (fully verified), `plausible`
  (verifiable hosts/QIDs but a gap the graph can't confirm), `rejected` (dropped). Never let
  plausible masquerade as grounded.

**Acceptance:** soundness metric = 1.0 for everything labeled `grounded`; scoring components
are inspectable; eval shows ranking improved (documented high-impact paths rank above noise).

## Phase 5 — Production hardening

Goal: extremely production-ready.

- **Observability:** structured logging per agent (model, tokens in/out, latency, tool calls,
  cache hits), a per-run trace object persisted alongside the analysis, and token/cost
  accounting surfaced in the run record.
- **Resilience:** timeouts + bounded retries with backoff on provider calls; every LLM JSON
  parse guarded by schema validation with a repair-or-drop path; partial results preserved on
  failure (never lose the deterministic layer).
- **Determinism/reproducibility:** temperature 0 (or documented) for classification/detection,
  content-hash caching so identical inputs give identical outputs, model id recorded in every
  cached/persisted artifact.
- **Config:** all thresholds, budgets, model ids, and heuristics in `core/config.py` (or env),
  nothing magic inline.
- **Performance:** classify findings in parallel within a bounded worker pool; cache
  aggressively; keep `compute_deterministic` token-free and instant.
- **Docs:** update `docs/AGENTS.md` (and any architecture note) with the new pipeline, the tool
  contract, the scoring formula, and how to run the eval harness. Update relevant memory/CLAUDE
  notes if present.

## Testing & Definition of Done

- `pytest` green, including: Phase 0 eval regression test, no-oracle-leakage test, capability
  classifier unit tests, graph generality test on the synthetic fixture, hop-verification
  soundness test, and a graceful-degradation test (provider disabled → deterministic output
  identical to pre-change).
- Eval metrics reported for both datasets: precision, recall, F1, soundness (=1.0 for
  grounded), hallucination rate (=0), plus a before/after comparison table vs the Phase 0
  baseline.
- No regression in existing API responses/schema consumed by the frontend; if you must extend
  the schema, make it additive and note it.
- A concise `CHANGES.md` (or PR description) summarizing what changed, the new metrics, and any
  decisions/tradeoffs.

## Ways of working

- Go phase by phase. After each phase: run the eval harness, report the metric delta, and
  pause for confirmation before the next phase.
- Prefer extending existing modules over rewrites; match the surrounding code style, comment
  density, and the existing "deterministic-first, AI-additive" architecture.
- If a change needs a new heavy dependency or an external network/data source (EPSS/KEV feeds,
  a new model), **stop and ask first** with the tradeoff.
- Keep commits small and labeled by phase. Do not commit or push unless asked; if you branch,
  branch from `rework`.
- If anything in the real code contradicts this brief (file moved, oracle located elsewhere,
  provider abstraction differs), trust the code, say so, and adapt rather than forcing the plan.

## Open decision points (answer these before/early, don't stall on them)

1. **External exploit feeds** — may the agent add EPSS/KEV enrichment (network/data
   dependency), or stay with in-dataset GRS/ACW/CVSS only?
2. **Model choice** — which model for the new LLM classification + detection passes?
3. **Schema changes** — additive-only is assumed; confirm if the frontend contract may grow.
