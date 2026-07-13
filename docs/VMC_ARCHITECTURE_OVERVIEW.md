# VMC — Vulnerability Management Center
## Multi-Agent, Provider-Agnostic Exposure Management Platform
### Architecture Overview

---

## 0. Positioning

This is **not** VOC/VOCI's kill-chain analyzer repurposed. It's a different product with a different center of gravity:

| | VOCI / VOC | **VMC (this system)** |
|---|---|---|
| Input | One CVE, or a curated enterprise dataset | **Any raw scanner CSV** (Qualys/Nessus/Rapid7/generic) — messy, real-world, per-team |
| Core value | Kill-chain reconstruction, compliance orchestration | **Ingest → Enrich → Triage → Explain → Route**, with live threat intel (EPSS, CISA KEV, exploit availability) |
| AI dependency | Gemini only | **Provider-agnostic** — Groq, Gemini, OpenAI, Anthropic, local Ollama, hot-swappable per agent |
| Analogy | Custom-built kill-chain tool | **Tenable Hexa AI-style agentic exposure management**: an analyst-in-the-loop system that does the triage grunt work an exposure-management team does by hand |
| Trust model | AI-scored | **Deterministic, explainable core risk engine** + AI as a contextual reasoning layer on top — every score is auditable and reproducible without re-calling an LLM |

The central design bet: **the risk score must be explainable and reproducible**, because this will sit in front of security leaders and auditors. LLMs enrich, correlate, and explain — they do not silently produce an opaque number. This is the single biggest architectural decision in the whole system, and it shapes everything below (Agent 5 in particular).

---

## 1. High-Level Flow

```
                     ┌─────────────────────────────────────────┐
                     │              OPERATOR (UI)               │
                     │  Upload: findings.csv + architecture.md  │
                     │          + architecture.png (optional)   │
                     └───────────────────┬───────────────────────┘
                                          │
                                          ▼
                     ┌─────────────────────────────────────────┐
                     │              ORCHESTRATOR                 │
                     │   async DAG · run registry · retries ·    │
                     │   per-agent model routing · job queue     │
                     └───────────────────┬───────────────────────┘
                                          │
       ┌───────────┬───────────┬─────────┼─────────┬───────────┬───────────┐
       ▼           ▼           ▼         ▼         ▼           ▼           ▼
    Agent 1     Agent 2     Agent 3   Agent 4   Agent 5     Agent 6     Agent 7
    Ingest      Topology    Threat    Attack    Risk        Compliance  Remediation
    &           &           Intel     Path      Scoring     Mapping     Orchestration
    Normalize   Segmentation Enrich   Discovery Engine
   (non-AI)     (non-AI)    (AI+tool) (AI)      (hybrid)    (non-AI)    (AI)
                                          │
                                          ▼
                                       Agent 8
                                    SLA & Predictive
                                    Analytics (non-AI)
                                          │
                                          ▼
                                       Agent 9
                                    Reporting & Dashboard
                                    Data Assembly (non-AI)
                                          │
                                          ▼
                     ┌─────────────────────────────────────────┐
                     │        REAL-TIME DASHBOARD (React)        │
                     │  Triage board · Attack paths · Team boards │
                     │  Compliance · What-if · Audit trail        │
                     └─────────────────────────────────────────┘
```

Agents 1–2 run in parallel (pure data agents, no LLM). Agent 3 (enrichment) can run per-CVE in parallel batches. Agent 4 depends on 1–3. Agent 5 depends on 1–4. Agents 6–9 depend on 5. The Orchestrator expresses this as an explicit DAG, not a fixed linear pipeline — this matters for scalability (see §7).

---

## 2. Shared State — `ExposureContext`

Same philosophy as VOCI's `AgentContext` / VOC's `VulnContext`: one mutable, strongly-typed (Pydantic) object threaded through the whole DAG, serialized to Postgres after every stage for resumability and audit trail.

```python
class ExposureContext(BaseModel):
    run_id: str
    tenant_id: str

    # Agent 1 output
    findings: list[Finding]                      # raw, normalized CVE + misconfig + excess-access rows
    assets: dict[str, Asset]                      # hostname/IP -> Asset
    teams: dict[str, TeamInfo]
    data_quality_issues: list[DataQualityIssue]

    # Agent 2 output
    topology: NetworkGraph                        # nodes = zones/VLANs, edges = trust/firewall rules
    segmentation_findings: list[SegmentationFinding]
    diagram_vs_markdown_conflicts: list[str]       # vision-model cross-check discrepancies

    # Agent 3 output
    enrichment: dict[str, ThreatIntel]             # cve_id -> {epss, kev, exploit_maturity, refs}

    # Agent 4 output
    attack_paths: dict[str, AttackPath]
    choke_points: list[ChokePoint]

    # Agent 5 output — THE CORE PRODUCT
    risk_register: dict[str, RiskAssessment]       # finding_id -> explainable score + breakdown

    # Agent 6 output
    compliance_register: dict[str, ComplianceFinding]

    # Agent 7 output
    remediation_plans: dict[str, RemediationPlan]  # team_id -> plan

    # Agent 8 output
    sla_dashboard: dict[str, SLAStatus]
    risk_trend_forecast: RiskForecast

    # Agent 9 output
    dashboard_bundle: DashboardBundle

    # Meta
    agent_logs: list[AgentLog]
    errors: list[AgentError]
    timing_ms: dict[str, float]
```

---

## 3. The Provider-Agnostic AI Layer (core differentiator)

This is the piece that doesn't exist in VOCI/VOC and is the main new engineering surface.

### 3.1 `LLMProvider` interface

```python
class LLMProvider(Protocol):
    async def generate_json(
        self, *, system: str, prompt: str,
        schema: type[BaseModel], temperature: float,
        tools: list[ToolSpec] | None = None,
    ) -> BaseModel: ...

    async def generate_with_vision(
        self, *, system: str, prompt: str, images: list[bytes],
        schema: type[BaseModel], temperature: float,
    ) -> BaseModel: ...
```

Concrete adapters: `GeminiProvider`, `GroqProvider`, `OpenAIProvider`, `AnthropicProvider`, `OllamaProvider`. Each adapter is responsible for:
- translating the Pydantic schema into that provider's structured-output / JSON-mode mechanism (native JSON mode where available, else a strict "return only JSON matching this schema" system prompt + a repair-retry loop)
- translating the internal `ToolSpec` into that provider's function-calling format
- normalizing errors (rate limit, context length, auth) into a shared `ProviderError` taxonomy so the retry/back-off logic in the Orchestrator doesn't need to know which vendor failed

### 3.2 `ModelRouter` — per-agent, per-tenant model selection

A YAML/DB-backed policy, not hardcoded:

```yaml
agents:
  threat_intel_enrichment:
    provider: groq          # fast + cheap, high volume, per-CVE classification
    model: llama-3.3-70b
    temperature: 0.1
  attack_path_discovery:
    provider: gemini        # long-context reasoning across 40+ findings + topology
    model: gemini-2.5-pro
    temperature: 0.4
  remediation_orchestration:
    provider: anthropic
    model: claude-sonnet-4-6
    temperature: 0.2
  vision_topology_check:
    provider: gemini
    model: gemini-2.5-pro   # needs vision
fallback_chain: [gemini, anthropic, groq, ollama]   # offline/air-gapped -> ollama last resort
```

This directly satisfies "provider-independent" and "supports multiple AI provider APIs": swapping Groq for Anthropic for one agent is a config change, not a code change. The `fallback_chain` also gives resilience — if Gemini is rate-limited mid-run, Agent 4 retries on the next provider in the chain automatically.

### 3.3 Structured output & retry contract (shared by every AI agent)

Every AI agent follows the same contract, generalized from VOCI's `GeminiClient`:
1. Build prompt + Pydantic schema.
2. Call `provider.generate_json(...)`.
3. On JSON parse/validation failure: 1 repair retry with the validation error appended to the prompt ("your last response failed schema X because Y — fix and resend").
4. On provider error: exponential back-off (1s → 2s → 4s), then fall through `fallback_chain`.
5. On total exhaustion: required agents abort the run with a structured error; optional agents (e.g., vision cross-check) degrade gracefully and the run continues with a flagged gap.

### 3.4 Tool-calling abstraction (for Agent 3's web/API enrichment)

Agent 3 needs to call external services (NVD, CISA KEV feed, EPSS API, optionally a web-search tool) regardless of which model is driving it. Tools are defined once as plain async Python functions with a `ToolSpec` (name, JSON schema, handler) and the provider adapter maps them into that vendor's tool-calling format. This means the same `fetch_epss(cve_id)` tool works whether Groq or Gemini is currently driving Agent 3.

---

## 4. The 9 Agents

### Agent 1 — Ingestion & Normalization (non-AI, deterministic)
- Multi-format CSV auto-detection (Qualys/Nessus/Rapid7/generic), same sniffing approach as VOCI's `DataAgent` but **not filtered by a single CVE** — loads the full findings set, all categories: CVE, misconfiguration, excessive-access, cloud misconfig, compliance-gap rows (as seen in `ghrab_vulnerabilities.csv`'s `Category` column).
- Parses `architecture.md` into a typed `NetworkGraph` (zones, VLANs, owning teams, compliance scope, documented trust edges).
- Maps every finding's `IP_Address`/`Hostname` to an `Asset` (VLAN, zone, owning team, criticality tier).
- Emits `DataQualityIssue`s for orphaned IPs, ambiguous ownership, unparseable rows — surfaced to the operator, never silently dropped.

### Agent 2 — Network Topology & Segmentation (non-AI + optional vision cross-check)
- Deterministic segmentation health scoring (Green/Yellow/Red) exactly as in VOC Agent 2.
- **New:** an optional vision sub-step — feeds the architecture PNG to a vision-capable model and asks it to extract zones/edges independently, then diffs that against the markdown-derived graph. Any mismatch (e.g., diagram shows a trust edge the markdown doesn't mention) becomes a `diagram_vs_markdown_conflict` — this is a genuinely useful "context understanding" feature the user asked for and a good showcase of multimodal input.

### Agent 3 — Threat Intelligence Enrichment (AI + tool-calling) — **the Hexa-AI-style piece**
- For every distinct CVE in the dataset (not per finding — dedup first, this is a big cost/latency win at scale):
  - Tool call → **CISA KEV** (is it in the Known Exploited Vulnerabilities catalog — binary, huge risk signal)
  - Tool call → **EPSS** (exploit prediction score, 0–1 probability of exploitation in the wild in the next 30 days)
  - Tool call → **NVD** (canonical CVSS if the CSV's own CVSS looks stale or missing)
  - Optional `web_search` tool call for very recent CVEs not yet in the above feeds (active-exploitation news, vendor advisories)
- Output per CVE: `ThreatIntel { epss_score, in_kev, exploit_maturity (weaponized/PoC/theoretical), first_seen_exploited, source_urls }`
- **Caching is mandatory here**: same CVE across many tenants/runs should hit a shared Redis/Postgres cache with a TTL (24h) before calling any external API or LLM — this is the highest-volume, most-repeatable agent in the system and the one most worth optimizing for cost at scale.
- This agent is the one that most needs a *fast, cheap* model (Groq/Llama-class) since it's doing high-volume tool-orchestration and light classification, not deep reasoning.

### Agent 4 — Attack Path Discovery & Correlation (AI, creative temp ≈0.4)
- Directly analogous to VOC's Agent 3: correlates all findings + topology + segmentation findings into realistic multi-step chains (reuses the `attack_path_refs`/`PATH-X-StepN` convention already present in the sample CSV/diagram as ground truth or RAG corpus when available; otherwise discovers paths from scratch).
- Also identifies **choke points** (single fixes that collapse multiple paths — e.g., Zerologon + the VLAN 10↔40 flat-trust rule together account for most of Path E's feasibility) — this is what makes the eventual remediation plan efficient rather than a flat sorted CVE list.

### Agent 5 — Risk & Criticality Scoring Engine (hybrid: deterministic core + AI contextualizer) — **the crown jewel**
This is where "triage them, sort them in a perfectly done risk-based and criticality-based classification" actually happens, and it's built explainable by design:

```
final_score (0-100) =
      w1 * cvss_normalized
    + w2 * epss_score              (from Agent 3)
    + w3 * kev_boolean * K         (from Agent 3 — large fixed boost, exploited-in-wild is decisive)
    + w4 * asset_criticality_tier  (from Agent 1 — crown-jewel weighting)
    + w5 * attack_path_multiplier  (from Agent 4 — appears in N paths / is a choke point)
    + w6 * compliance_scope_boost  (from Agent 6 — in PCI CDE / SWIFT scope)
    + w7 * exposure_boost          (internet-facing vs internal-only, from Agent 1/2)
    - w8 * compensating_controls   (WAF/EDR/segmentation partially mitigating, from Agent 4)
```
- Weights (`w1..w8`) live in a versioned, tenant-configurable policy (not hardcoded), so a bank can weight compliance heavier than a SaaS startup does.
- The **formula itself never touches an LLM** — anyone can recompute a finding's score by hand from the stored inputs. That's the trust property.
- An AI sub-step then takes the computed score + all its inputs and generates a **one-paragraph plain-English justification** per finding ("Scored 92/100 — Critical: actively exploited (CISA KEV), sits at the entry point of Path E which reaches the SWIFT gateway, and the affected asset is in PCI CDE scope.") — this is explanation, not scoring, and is clearly labeled as such in the data model (`RiskAssessment.ai_explanation` is a separate field from `RiskAssessment.score` and its `score_breakdown`).
- Output feeds the sortable/filterable triage board that's the main operator-facing screen.

### Agent 6 — Compliance & Governance Mapping (non-AI, template-driven)
- Same as VOC Agent 5 — deterministic control mapping (PCI DSS, SWIFT CSP, ISO 27001, NIST CSF, CIS Controls), driven by a static framework-to-keyword/category mapping table plus each finding's `Compliance_Ref` column when present in the CSV.

### Agent 7 — Remediation Orchestration & Routing (AI, factual temp ≈0.2)
- Groups by `Responsible_Team`, sequences by `Agent 5` score and `Agent 4` dependency chains (fix the choke point before its dependents), estimates effort/cost, detects resource conflicts across teams — same shape as VOC Agent 6.
- Emits step-by-step playbooks per finding, reusing the CSV's own `Remediation` field as a grounding source (never hallucinated from nothing) plus AI-generated sequencing/rollback/validation steps around it.

### Agent 8 — SLA & Predictive Analytics (non-AI)
- Burndown projections, team velocity, time-to-compliance forecasting, residual-risk-after-remediation estimation — same shape as VOC Agent 8. Pure math over `remediation_plans` + historical completion data; no LLM needed and none should be used here (predictable, auditable numbers).

### Agent 9 — Reporting & Dashboard Data Assembly (non-AI)
- Assembles the final `DashboardBundle`: triage board rows, attack-path graph data (Cytoscape-ready, reusing VOCI's `GraphAgent` styling approach), team boards, compliance reports (Jinja2 → Markdown/PDF), risk heatmap, executive summary.

---

## 5. Orchestrator Design

- **DAG, not a fixed pipeline.** Implemented with a lightweight async task graph (either hand-rolled `asyncio.gather`/topological sort, or LangGraph if you want built-in state-machine/branching/retry semantics — recommended for this system specifically because several agents are optional/degradable and LangGraph's conditional edges model that cleanly).
- Node types: `required` (pipeline aborts on failure) vs `optional` (logs + degrades, e.g. vision cross-check, web-search enrichment for very new CVEs).
- Each node call is wrapped identically to VOCI's `_run()`: timed, logged, retried per the provider contract in §3.3, and written to `agent_logs`.
- Runs are persisted as rows in Postgres (`run_id`, current stage, full `ExposureContext` snapshot after each stage) so a run can be **resumed** rather than restarted if it dies at Agent 6 of 9 — important once datasets get to hundreds/thousands of findings.

---

## 6. Data Model — Key Pydantic Types

```python
class Finding(BaseModel):
    finding_id: str
    cve_id: str | None
    category: str                  # Missing Patch / Misconfiguration / Excessive Access / Cloud Misconfig / Compliance Gap
    title: str
    severity_raw: str
    cvss_score: float | None
    cvss_vector: str | None
    asset_ip: str
    asset_hostname: str
    vlan_id: str | None
    zone: str
    port: str | None
    description: str
    consequence: str
    remediation_text: str
    patch_available: bool | None
    responsible_team: str
    attack_path_refs: list[str]
    compliance_refs: list[str]
    status: str

class Asset(BaseModel):
    hostname: str
    ip: str
    vlan_id: str | None
    zone: str
    owning_team: str
    criticality_tier: int          # 0 = crown jewel .. 3 = general purpose
    compliance_scope: list[str]

class ThreatIntel(BaseModel):
    cve_id: str
    epss_score: float | None
    in_kev: bool
    exploit_maturity: Literal["weaponized","poc","theoretical","unknown"]
    sources: list[str]
    fetched_at: datetime

class RiskAssessment(BaseModel):
    finding_id: str
    score: float                            # 0-100, deterministic
    score_breakdown: dict[str, float]        # every weighted term, auditable
    band: Literal["Critical","High","Medium","Low"]
    ai_explanation: str                      # plain-English, clearly separate from the score itself
    policy_version: str                      # which weight config produced this score
```

---

## 7. Scalability & Deployment

| Concern | Approach |
|---|---|
| Large CSVs (1000s of findings) | Agent 1 streams/chunks the CSV; Agent 3 dedups by CVE before enrichment (a 5,000-row CSV might only have 200 distinct CVEs); Agent 4/5/7 batch-process findings in parallel worker pools |
| Concurrent tenants/runs | FastAPI (async) + Celery/RQ workers on Redis for the actual agent DAG execution, so the HTTP layer never blocks on a multi-minute run; WebSocket channel per `run_id` for live progress |
| Cost control at scale | Per-agent model routing (cheap model for high-volume Agent 3, capable model only for Agent 4/5's reasoning); aggressive caching of `ThreatIntel` (shared across tenants — a CVE's EPSS score isn't tenant-specific) |
| Offline / air-gapped deployments | `OllamaProvider` as the last entry in every agent's `fallback_chain`; Agent 3's external tool calls (KEV/EPSS/NVD) degrade gracefully to "using dataset CVSS only, threat-intel enrichment unavailable offline" rather than hard-failing |
| Storage | PostgreSQL for `ExposureContext` snapshots + audit trail (compliance-grade, same rationale as VOC); Redis for enrichment cache + job queue + live run state |
| Explainability at scale | `RiskAssessment.score_breakdown` and `policy_version` stored per finding — re-running a report six months later with the same policy version reproduces bit-identical scores without any LLM call |

---

## 8. Frontend (reuses VOCI's proven pattern, extended)

Three primary screens:
1. **Triage Board** — the main new screen this platform needs that VOCI didn't have: sortable/filterable table of every finding, `RiskAssessment.score` + band + `ai_explanation`, group-by team/category/compliance-scope, click-through to attack-path context.
2. **Attack Path View** — Cytoscape.js kill-chain rendering, directly reusing VOCI's `GraphAgent`/styling approach, extended to multi-path (VOC-style).
3. **Team Boards + Compliance Dashboard** — Kanban-style per-team remediation boards with SLA burndown, and the PCI/SWIFT/ISO compliance screens — same shape as VOC's Screens 3–4.

---

## 9. Tech Stack Summary

| Layer | Choice | Why |
|---|---|---|
| AI/LLM | Custom `LLMProvider` abstraction over Gemini / Groq / OpenAI / Anthropic / Ollama | Provider independence is a hard requirement |
| Orchestration | Python async + (optionally) LangGraph for the DAG/state-machine | Conditional/optional-agent semantics fit LangGraph well |
| Backend | FastAPI (async) | Matches VOC/VOCI precedent, WebSocket-native |
| Job queue | Celery or RQ + Redis | Decouple long-running agent DAGs from HTTP request lifecycle |
| Database | PostgreSQL + SQLAlchemy | Audit trail, compliance-grade persistence, resumable runs |
| Cache | Redis | Threat-intel cache (cross-tenant), job state, rate-limit tracking |
| Frontend | React + TypeScript + Cytoscape.js + Recharts + WebSockets | Reuses VOCI's frontend investment directly |
| Reporting | Jinja2 → Markdown/PDF | Audit-ready compliance docs |
| External data | CISA KEV feed, FIRST.org EPSS API, NVD API | Free, no-auth-required (or free-tier) sources — good for a POC |

---

## 10. What Makes This "Hexa-AI-like" Specifically

Tenable's Hexa AI pitch is agentic exposure management that does analyst triage work autonomously while staying explainable and steerable. The concrete parallels built into this design:
- **Agent 3 (enrichment)** is the live-threat-context layer Hexa AI leans on (EPSS/KEV) instead of static CVSS-only scoring.
- **Agent 5** is deliberately not "ask the LLM for a risk score" — it's a transparent scoring engine an LLM explains, which is what makes it trustworthy enough for an operator to act on without re-deriving it by hand.
- **Agent 4's choke-point detection** is the "which 3 fixes matter most" reasoning that turns a flat 40-row CSV into a prioritized, minimal action plan — the actual point of agentic exposure management over a plain vulnerability scanner.
- **Provider independence** means this isn't a demo tied to one vendor's API pricing/availability — a real requirement for anything meant to run at an enterprise or be deployed air-gapped.
