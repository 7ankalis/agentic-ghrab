# CMDB Accuracy Brief — Real-Shaped Synthetic CMDB

**Audience:** implementing agents working on the VOC platform (`backend/`, `frontend/`).
**Status:** approved direction, not yet started.
**Supersedes for CMDB concerns:** the markdown-doc CMDB (`backend/data/*_architecture.md` +
`backend/core/cmdb.py`'s prose parser).

---

## 0. THE OBJECTIVE (read this first, re-read it before every commit)

> **Make the attack-path analysis genuinely accurate by giving the engine a *real
> enterprise CMDB* — synthetic, but structured and realistic exactly like a real
> company's CMDB (ServiceNow `cmdb_ci_*` + `cmdb_rel_ci`).**

"Accurate" has a precise, testable meaning here. Every change is judged against it:

1. **No missed attacks.** If a route from an attacker-reachable entry point to a crown
   jewel exists in the data, the engine surfaces it. Today paths are silently dropped.
2. **No invented attacks.** Every asserted hop maps to a real CI and a real, typed
   relationship (or an authoritative reachability rule). No fabricated reachability.
3. **No forbidden hops.** A hop the CMDB explicitly says cannot exist
   (`Should-Not-Exist`) is never present in output, deterministic or LLM.
4. **The number moves.** Accuracy is proven by precision/recall against a held-out
   oracle, measured *before and after* — not by narrative.

**This is not a "get real data" task. It is a "stop the pipeline from losing and
fabricating relationships, then feed it realistic structured data" task.** Read §2 —
the accuracy problems are structural. Swapping in richer data through the *current*
pipeline makes several of them worse. Fix the representation first (Phases 1 & 3),
then the realistic dataset (Phase 2) pays off.

**Invariants that must survive every phase** (do not regress these — they are enforced
by existing tests in `backend/eval/`):
- **Oracle isolation.** The documented attack paths (`data/<ds>/oracle/`, `core/oracle.py`,
  `core/graph.build_chains`, any `Attack_Path_Ref`) are used *only to score* detection —
  never fed to any classifier, graph, or agent. Guard: `eval/test_no_oracle_leakage.py`.
- **Deterministic-first, AI-additive.** The deterministic engine (GRS, capability
  classification, reachability graph, path discovery) is the source of truth and runs
  with zero API keys. LLM agents narrate/enrich; they never compute or override paths.
- **Graceful degradation.** No provider ⇒ deterministic layer produces identical output.
- **Bounded cost + cooperative cancellation** preserved.

---

## 1. Where we are (current CMDB)

- **Source of truth:** a hand-authored markdown doc per enterprise
  (`backend/data/ghrab_architecture.md`, `velon_architecture.md`, `elihowa_architecture.md`).
- **Parser:** `backend/core/cmdb.py` — regex + positional markdown-table parsing into
  `Zone` / `Asset` / `Team` / `dependency_edges` / `reachability_rules` / `cred_relations`.
- **Graph builder:** `backend/core/attack_graph.py` — composes CMDB records + per-finding
  capabilities into a `networkx.DiGraph`, enumerates INTERNET→crown-jewel paths.
- **LLM grounding:** `CMDB.grounding_context(max_chars=7000)` flattens everything to a
  truncated text blob fed to the agents.
- **Datasets:** multi-enterprise, runtime-switchable (`backend/core/datasets.py`,
  `/api/datasets` in `api/routes.py`). A dataset = a `*_vulnerabilities.csv` +
  `*_architecture.md` pair discovered on disk.

The data model *content* is good (it already mirrors ServiceNow). The problem is that it
lives in prose and is consumed lossily.

---

## 2. Root causes of inaccuracy (diagnosis — fix these, not "the data")

Verified by reading `core/cmdb.py`, `core/attack_graph.py`, and `data/ghrab_architecture.md`.

### 2.1 The authoritative reachability table is invisible to the deterministic graph — CRITICAL
`§3 Network Reachability Rule Base` is labelled *"THE authoritative reachability graph"*
in the doc, and every cross-zone hop is supposed to cite a `RULE-*` id. But
`attack_graph.build_graph` **never turns those rules into edges.** They are parsed into
plain strings (`cmdb.reachability_rules`) and handed *only to the LLM as text*. The actual
graph derives cross-zone reachability from same-VLAN lateral edges + `§4` dependency edges
+ *inferred* `capability.zone_transition`. Consequences:
- **Missed attacks:** an `Excessive` rule (e.g. VPN→Management split-tunnel) never becomes
  a traversable edge unless a finding's capability happens to infer that exact transition.
- **Invented / unverifiable attacks:** the LLM reads the rule text and asserts a crossing
  the deterministic graph cannot confirm → labelled `plausible` or contradicts the graph.
- **Forbidden hops not blocked:** nothing consumes `Should-Not-Exist` as a *veto*, so a
  hop the CMDB forbids can still appear via an inferred edge.

**This single gap is the largest accuracy defect. Phase 3 fixes it.**

### 2.2 Prose-as-database is lossy and fails silently
The entire CMDB is regex/positional-table-parsed from markdown. A renamed header or a
reshaped table returns an empty section **with no error** — the documented history of a
"CI-format parser bug that silently starved every agent" is exactly this failure mode.
Realistic data will trip it constantly.

### 2.3 Grounding truncation at 7000 chars drops the best relationships
`grounding_context(max_chars=7000)` flattens to text and cuts the tail — which is
*dependencies and hosting*, the highest-blast-radius relationships. A larger, realistic
CMDB overflows this and silently drops precisely the relationships that yield the strongest
paths. More realistic data ⇒ *worse* output under the current design.

### 2.4 Fuzzy entity resolution mis-maps CIs
`_resolve_asset` / `_resolve_host` match on `endswith` / substring. Messier real names →
edges attached to the wrong host.

### 2.5 No referential integrity
Nothing checks that every relationship endpoint, every `Valid On` CI, every RULE zone, and
every finding's host actually resolves to a real CI. Dangling references are skipped
silently — an invisible source of missed hops.

---

## 3. Target design — a synthetic CMDB shaped like a real enterprise's

**Key realization:** the realistic format and the accuracy fix are the *same move*. Real
enterprise CMDBs are relational tables (ServiceNow `cmdb_ci_*` + `cmdb_rel_ci`), exported
as CSV/JSON — **not** prose. Building the synthetic CMDB the way real companies actually
store it *is itself* the fix for §2.2 (lossy parser) and §2.5 (integrity).

### 3.1 Source of truth = structured relational tables

New dataset layout (example key: `acmebank`):

```
backend/data/acmebank/
  cmdb/
    cmdb_ci_network_segment.csv   # zones: ci_id, name, cidr, trust_level, owner_group
    cmdb_ci_server.csv            # ci_id, name, zone_id, ip, platform, criticality, support_group, business_service
    cmdb_ci_netgear.csv           # firewalls, load balancers, routers, switches
    cmdb_ci_appl.csv              # applications (relate to a server via "Runs on")
    cmdb_ci_database.csv          # database instances
    cmdb_ci_cloud_resource.csv    # S3 / RDS / IAM roles / Entra tenant
    cmdb_ci_service_account.csv   # identity / credential CIs
    cmdb_ci_business_service.csv  # business services (blast-radius / value anchor)
    cmdb_rel_ci.csv               # parent_ci, child_ci, rel_type   ← the relationship graph
    cmdb_rel_type.csv             # vocabulary: "Runs on::Runs", "Depends on::Used by", "Hosted on::Hosts", "Connects to::Connected by"
    net_reachability.csv          # firewall rule base: src_zone, dst_zone, port, status, enabling_qid, notes
    cred_rel.csv                  # identity_ci, valid_on_ci_ids, access_level, issue, enabling_qid
  vulnerabilities.csv             # scan export — SAME column shape as existing datasets
  oracle/
    attack_paths.md               # HELD-OUT ground-truth paths — NEVER fed to any agent
```

- `status` in `net_reachability.csv` ∈ {`Intended`, `Excessive`, `Should-Not-Exist`}.
- Every `*_ci` / `*_zone` / endpoint column MUST be a real `ci_id` defined in some table.
- Markdown, if kept at all, is a *rendering* of these tables — never an input.

### 3.2 Realism features — and the specific inaccuracy each one proves fixed

| Real-enterprise feature to build in | Inaccuracy it targets (§2 ref) |
|---|---|
| `net_reachability.csv` as a first-class table with `Excessive` + `Should-Not-Exist` rows | 2.1 — missed cross-zone attacks *and* invented/forbidden hops |
| Every relationship endpoint is a real `ci_id`; validator enforces | 2.4 / 2.5 — mis-mapped and silently-dropped edges |
| Credential CIs valid on multiple hosts (non-network pivots) | Lateral movement class a zone-only view misses |
| One hypervisor hosting many guests; one backup server reaching multiple DBs | High-blast-radius paths that truncation drops (2.3) |
| **Decoy/benign relationships** (legit app→DB with no exploitable finding) that must NOT yield a path | 2.1 — "shows things that are wrong" / false positives |
| Multiple graded paths (easy/medium/hard) to *distinct* crown jewels | "Lacks attacks" — proves all objectives surface, not just top-GRS |
| Realistic scale (~80–120 CIs; prod + DR + cloud; several business services) | Exercises grounding past the 7 KB ceiling (2.3) |
| A few seeded data-quality defects (one orphan CI, one stale relationship) | Proves the Phase-1 validator actually catches real-world mess |

Keep the dataset **referentially clean** (authoritative ground truth) except for the few
deliberately-seeded defects used to test the validator.

### 3.3 Keep it as a NEW dataset
Add `acmebank` alongside `ghrab`/`velon`/`elihowa` via the existing `core/datasets.py`
discovery. Do **not** delete the markdown datasets during development — they keep the
current tests green while the new structured path is built and validated in parallel.

---

## 4. Execution plan (accuracy-first ordering)

Each phase is independently shippable and testable. **Do not reorder** — Phases 1 & 3 fix
accuracy on any data; Phase 2 only pays off once the pipeline stops dropping/fabricating.

### Phase 1 — Structured schema + validating loader
- Pydantic models: `ConfigurationItem` (ci_id, ci_class, zone, ip, platform, criticality,
  support_group, business_service) and `Relationship` (rel_id, rel_type, source_ci,
  target_ci, port, status/flag, enabling_qid).
- A CSV loader (`core/cmdb.py` or a new `core/cmdb_store.py`) that produces the same
  in-memory interface the rest of the app already consumes (`zones`, `assets`, `teams`,
  `dependency_edges`, `reachability_rules`, `cred_relations`, `grounding_context`) so
  downstream code keeps working — the format changes underneath, the interface does not.
- **Referential-integrity validation that fails loud, not silent:** every relationship
  endpoint resolves to a real `ci_id`; every `net_reachability` zone exists; every
  finding's host maps to a CI. Emit a structured report (dangling refs, orphan CIs, zones
  with no rules, findings with no CI).
- Surface it: `GET /api/cmdb/validate` + a startup check that logs the report.
- **Fixes:** §2.2, §2.4, §2.5.

### Phase 2 — Author the `acmebank` synthetic CMDB
- Build every table in §3.1 with the realism features in §3.2.
- Write the held-out `oracle/attack_paths.md` (documented A–F style paths) — this is the
  scoring key ONLY; it never enters the pipeline (guard: `eval/test_no_oracle_leakage.py`).
- Register the dataset; confirm `GET /api/datasets` lists it and it validates clean
  (except the seeded defects, which the validator must report).

### Phase 3 — Graph consumes the full relationship model (BIGGEST accuracy win)
- In `attack_graph.build_graph`, build zone-to-zone edges directly from `net_reachability`:
  - `Intended` + `Excessive` → traversable edges, each carrying its `rule_id` + `enabling_qid`.
  - `Should-Not-Exist` → an explicit **blocked-pair set** that vetoes any inferred crossing
    between those zones (no other edge type may connect them).
- Every cross-zone hop now carries an authoritative `rule_id` — the deterministic graph and
  the LLM stop disagreeing, matching what the doc already promises.
- Replace fuzzy hostname resolution with exact `ci_id` resolution (trivial once CIs are
  structured — match on `SRV-...`, not a substring).
- **Fixes:** §2.1, §2.4.

### Phase 4 — Structured grounding for the agents (kill 7 KB truncation)
- The detection agent already uses read-only tools (`agents/detection_tools.py`). Add CMDB
  query tools so it reads *typed records on demand* instead of a truncated flattened blob:
  `reachability_rule(src, dst)`, `relationships_of(ci)`, `credentials_valid_on(ci)`,
  `business_service_of(ci)`.
- Accuracy stops depending on what fit in the first 7 KB.
- **Fixes:** §2.3.

### Phase 5 — Prove the accuracy gain (mandatory — this is the definition of done)
- Extend `backend/eval/detection.py` to run against `acmebank` vs its held-out oracle.
- Report target- and edge-level precision/recall/F1, soundness (must be 1.0 on grounded),
  hallucination (must be 0), ranking (AP/MRR) — the metrics the harness already computes.
- Commit a **baseline captured before Phase 3** and assert the after-numbers beat it. If
  precision/recall did not improve, the change failed its objective — do not merge.
- Add a regression test asserting: (a) no output hop crosses a `Should-Not-Exist` pair,
  (b) every `Excessive` rule that lies on a real INTERNET→crown route is discoverable.

---

## 5. Acceptance criteria (the objective, made checkable)

A phase is done only when all still hold:

- [ ] `eval/test_no_oracle_leakage.py` passes — oracle never entered the pipeline.
- [ ] `GET /api/cmdb/validate` reports the `acmebank` CMDB clean except the seeded defects,
      and it reports those defects explicitly (proves loud-failure works).
- [ ] Every asserted hop in `/attack-paths` output carries a real `ci_id` + a real
      `rel_type` or `rule_id`. Hallucination rate = 0.
- [ ] No output hop crosses a `Should-Not-Exist` zone pair (deterministic OR LLM).
- [ ] Every documented oracle path A–F is re-discovered from the structured CMDB alone.
- [ ] Decoy/benign relationships produce **no** attack path.
- [ ] Precision/recall/F1 on `acmebank` **strictly beat** the pre-Phase-3 baseline.
- [ ] With no provider configured, deterministic output is unchanged (graceful degradation).
- [ ] Existing markdown datasets (`ghrab`/`velon`/`elihowa`) still load and pass their tests.

## 6. Explicit non-goals / guardrails

- **Do not** feed the oracle, `Attack_Path_Ref`, or `oracle/attack_paths.md` into any
  classifier, graph, or agent — scoring only.
- **Do not** let the LLM name hosts/zones/edges that aren't in the CMDB; pivots stay
  derived deterministically. The LLM narrates and prioritizes; it does not invent topology.
- **Do not** delete or break the markdown datasets during migration.
- **Do not** claim an accuracy improvement without the before/after eval numbers (§5).
- Keep every new weight/threshold/token in `core/config.py`, not inline — matches the
  existing convention.

---

## 7. Suggested starting point

Begin with **Phase 1 + Phase 2 together**: the schema, the validating CSV loader, and a
first realistic cut of the `acmebank` tables — they are the foundation everything else
verifies against. Land Phase 3 immediately after (it is where the accuracy actually moves),
then Phases 4–5. Keep `core/cmdb.py`'s public interface stable so `attack_graph.py`,
`orchestrator.py`, and the serializers keep working while the format changes underneath.
