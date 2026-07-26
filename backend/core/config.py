"""
Central configuration: provider registry, agent-to-provider assignment, paths.

Design intent: the platform must never hard-depend on a single LLM vendor.
Every agent role has a *preferred* provider (spread across vendors on purpose,
so a full pipeline run doesn't hammer one provider's rate limit / bill), plus
an ordered fallback chain used automatically if the preferred key isn't set.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT_DIR / "data"
CACHE_DIR = DATA_DIR / "cache"
CACHE_DIR.mkdir(parents=True, exist_ok=True)
# Per-finding LLM capability classifications are cached here keyed by a hash of
# the finding content + model id, so re-runs are token-free and deterministic
# (Phase 1 of the intelligence brief). Safe to delete; it only ever re-populates.
CAPABILITY_CACHE_DIR = CACHE_DIR / "capability"

# The risk-scoring methodology is shared across every enterprise (it encodes
# EPSS/KEV/DORA scoring rules, not org-specific data), so unlike the per-org
# vulnerabilities CSV + architecture doc it stays a fixed path.
RISK_METHODOLOGY_MD_PATH = DATA_DIR / "ghrab_risk_methodology.md"

# SQLite by default (zero-ops, file-based) — swapping to Postgres in prod is a
# DATABASE_URL env change, nothing else, since access only ever goes through
# db/repository.py's SQLAlchemy layer.
DATABASE_URL = os.environ.get("DATABASE_URL", f"sqlite:///{DATA_DIR / 'voc.db'}")


# --- Active dataset accessors --------------------------------------------------
# Which enterprise is being scanned is now runtime-switchable (see
# core/datasets.py + api/routes.py's /datasets endpoints), not a fixed constant.
# These thin accessors resolve the currently active dataset at call time; import
# is deferred to avoid a circular import (datasets.py imports DATA_DIR above).
def active_vuln_csv() -> Path:
    from core.datasets import get_active
    return get_active().vuln_csv


def active_architecture_md() -> Path:
    from core.datasets import get_active
    return get_active().architecture_md


def active_cmdb_dir() -> Path | None:
    """The relational CMDB directory (cmdb_ci_*.csv + cmdb_rel_ci.csv) for the
    active dataset, or None for a legacy markdown dataset. CMDB.load() branches on
    this: a directory ⇒ CSV-backed structured load, None ⇒ markdown parse."""
    from core.datasets import get_active
    return get_active().cmdb_dir


def active_dataset_key() -> str:
    """The persistence/scoping key every analysis_run row is stored under, so
    switching enterprise never mixes one dataset's run history into another's
    duplicate-detection or trend queries."""
    from core.datasets import get_active
    return get_active().key


def active_org() -> dict[str, str]:
    """Per-org framing for the LLM analyst persona (agents/base.py) so agent
    narratives describe the active enterprise's sector + compliance frameworks."""
    from core.datasets import get_active
    d = get_active()
    return {"name": d.name, "sector": d.sector, "frameworks": d.frameworks}

@dataclass(frozen=True)
class ProviderSpec:
    key: str                 # internal id, e.g. "anthropic"
    label: str                # display name
    env_var: str               # env var / session-state key holding the API key
    default_model: str          # sane default model id for this provider
    litellm_prefix: str          # prefix litellm expects, "" if none needed
    docs_hint: str = ""          # short note shown in Settings UI


PROVIDERS: dict[str, ProviderSpec] = {
    "anthropic": ProviderSpec(
        key="anthropic", label="Anthropic (Claude)", env_var="ANTHROPIC_API_KEY",
        default_model="claude-opus-4-8", litellm_prefix="anthropic",
        docs_hint="console.anthropic.com",
    ),
    "openai": ProviderSpec(
        key="openai", label="OpenAI (GPT)", env_var="OPENAI_API_KEY",
        default_model="gpt-4.1", litellm_prefix="openai",
        docs_hint="platform.openai.com",
    ),
    "groq": ProviderSpec(
        key="groq", label="Groq", env_var="GROQ_API_KEY",
        default_model="llama-3.3-70b-versatile", litellm_prefix="groq",
        docs_hint="console.groq.com — fast + cheap, good for high-volume triage",
    ),
    "mistral": ProviderSpec(
        key="mistral", label="Mistral", env_var="MISTRAL_API_KEY",
        default_model="mistral-large-latest", litellm_prefix="mistral",
        docs_hint="console.mistral.ai",
    ),
    "gemini": ProviderSpec(
        key="gemini", label="Google (Gemini)", env_var="GEMINI_API_KEY",
        default_model="gemini-2.0-flash", litellm_prefix="gemini",
        docs_hint="aistudio.google.com/apikey — flash tiers are free-tier available",
    ),
    "deepseek": ProviderSpec(
        key="deepseek", label="DeepSeek", env_var="DEEPSEEK_API_KEY",
        default_model="deepseek-chat", litellm_prefix="deepseek",
        docs_hint="platform.deepseek.com",
    ),
    "xai": ProviderSpec(
        key="xai", label="xAI (Grok)", env_var="XAI_API_KEY",
        default_model="grok-4", litellm_prefix="xai",
        docs_hint="console.x.ai",
    ),
}

# Each agent role gets a distinct *preferred* provider by default (spreads load /
# cost across vendors) plus a fallback order. The operator can override any of
# this from the Settings tab; overrides live in st.session_state.
AGENT_ROLES = [
    "capability",      # per-finding LLM capability extraction (hybrid classifier)
    "correlation",     # cross-references CMDB + findings + attack paths
    "attack_path",      # analyst-style narration of attack chains
    "remediation",       # enriches remediation guidance beyond the raw CSV
    "compliance",         # compliance / regulatory reasoning
    "triage",               # executive synthesis / chat analyst
]

# Defaults favour the providers most likely to be configured in this deployment
# (Gemini/Groq/Mistral), spread across vendors so a full pipeline run doesn't
# hammer one bill/rate-limit. Any of these is overridable from Settings, and the
# fallback chain below is tried automatically when the preferred key is absent.
DEFAULT_AGENT_PROVIDER: dict[str, str] = {
    "capability": "mistral",     # per-finding structured extraction, high volume
    "correlation": "mistral",       # fast, high-volume cross-referencing
    "attack_path": "mistral",    # large-context reasoning for chain analysis
    "remediation": "mistral",
    "compliance": "mistral",
    "triage": "mistral",         # executive synthesis + analyst chat
}

# Per-role model on the role's *preferred* provider (above). Task difficulty and
# call volume are matched to each Mistral model's free-tier throughput (see the
# RPS/TPM caps encoded in MODEL_MIN_INTERVAL): the strong-but-slow medium model
# for the low-volume reasoning roles, the fast high-throughput small model for the
# high-volume / interactive / batched roles. Only applied when we're actually on
# the role's preferred provider — a fallback provider uses its own default model,
# since these ids are Mistral-specific. Override per session from Settings.
DEFAULT_AGENT_MODEL: dict[str, str] = {
    "capability": "mistral-small-2506",   # batched, high-volume structured extraction
    "correlation": "mistral-medium-2505",  # cross-finding reasoning (toxic combos)
    "attack_path": "mistral-medium-2505",  # core attack-chain reasoning + detection
    "remediation": "mistral-small-2506",   # interactive per-finding drill-in (low latency)
    "compliance": "mistral-small-2506",    # structured framework mapping
    "triage": "mistral-medium-2505",       # executive synthesis + analyst chat (prose)
}

# Per-role sampling temperature. Determinism/reproducibility (Phase 5): every role
# that produces STRUCTURED output a downstream stage parses — capability extraction,
# detection, correlation, compliance, remediation — samples at 0 so identical inputs
# give identical outputs (and content-hash caching is meaningful). Only `triage`
# (free-text executive synthesis + analyst chat) keeps a documented, non-zero
# temperature, since there a little variation reads as more natural prose and nothing
# downstream parses it. capability_llm / the detection ReAct loop pass their own
# explicit 0 (CAPABILITY_LLM_TEMPERATURE / DETECTION_AGENT_TEMPERATURE) and don't go
# through this map; it governs the agents/base.py `ask`/`ask_json` helpers.
DEFAULT_AGENT_TEMPERATURE: dict[str, float] = {
    "capability": 0.0,
    "correlation": 0.0,
    "attack_path": 0.0,
    "remediation": 0.0,
    "compliance": 0.0,
    "triage": _env_float("TRIAGE_TEMPERATURE", 0.2),  # prose synthesis — documented non-zero
}


def agent_temperature(role: str) -> float:
    """Sampling temperature for a role's `ask`/`ask_json` calls. Unknown roles get
    0.0 (deterministic) — a safe default for anything structured."""
    return DEFAULT_AGENT_TEMPERATURE.get(role, 0.0)


FALLBACK_ORDER = ["mistral", "groq", "gemini", "anthropic", "openai", "deepseek", "xai"]

# --- Client-side rate limiting -------------------------------------------------
# Free provider tiers cap requests-per-minute (Gemini flash ~15 RPM, Mistral free
# ~1 RPS, Groq ~30 RPM). A full pipeline run fires ~6 calls back-to-back, which
# trips those caps instantly. We therefore (a) space consecutive calls to the
# SAME provider by a minimum interval, and (b) on a 429 we back off and retry the
# same provider instead of immediately burning through the fallback chain (whose
# providers are just as rate-limited). All tunable via env without a code change.
# (_env_float / _env_int are defined at the top of this module.)

# Default minimum seconds between two requests to the same provider.
LLM_MIN_INTERVAL_SEC = _env_float("LLM_MIN_INTERVAL_SEC", 4.0)
# Per-provider overrides (seconds) — tuned to each free tier's RPM. Anything not
# listed falls back to LLM_MIN_INTERVAL_SEC.
PROVIDER_MIN_INTERVAL: dict[str, float] = {
    "groq": _env_float("LLM_MIN_INTERVAL_GROQ", 2.5),      # ~30 RPM free
    "gemini": _env_float("LLM_MIN_INTERVAL_GEMINI", 4.5),  # ~15 RPM free
    "mistral": _env_float("LLM_MIN_INTERVAL_MISTRAL", 1.5),
}
# Retry the SAME provider this many times on a rate-limit (429) before falling
# through to the next provider in the chain.
LLM_MAX_RETRIES = _env_int("LLM_MAX_RETRIES", 4)
# Exponential backoff base; wait = base * 2**attempt (capped), or Retry-After.
LLM_BACKOFF_BASE_SEC = _env_float("LLM_BACKOFF_BASE_SEC", 5.0)
LLM_BACKOFF_MAX_SEC = _env_float("LLM_BACKOFF_MAX_SEC", 60.0)
# Hard per-request wall-clock cap (seconds) handed to the provider HTTP client, so
# a hung/slow provider can't stall a whole run indefinitely — retries + backoff
# bound *how many* failures we tolerate, this bounds *how long* one attempt waits.
# A timeout is treated as a retryable error (same-provider retry, then fallback),
# exactly like a 429. Tunable via env; 0 disables the client timeout.
LLM_REQUEST_TIMEOUT_SEC = _env_float("LLM_REQUEST_TIMEOUT_SEC", 60.0)


def provider_min_interval(provider_key: str) -> float:
    return PROVIDER_MIN_INTERVAL.get(provider_key, LLM_MIN_INTERVAL_SEC)


# Per-MODEL request spacing (seconds), derived from each Mistral model's free-tier
# Requests-Per-Second cap as interval ≈ 1.15 / RPS (15% headroom). Free-tier RPS
# varies wildly by model — mistral-small-2506 allows 5 RPS but mistral-large-2512
# only 0.07 — so the client throttle must key on the model, not just the provider
# (see providers._throttle). A model absent here falls back to the provider
# interval. Tune via env if the published caps change.
MODEL_MIN_INTERVAL: dict[str, float] = {
    "mistral-small-2506": _env_float("LLM_MIN_INTERVAL_MISTRAL_SMALL", 0.25),    # 5.00 RPS
    "mistral-medium-2505": _env_float("LLM_MIN_INTERVAL_MISTRAL_MEDIUM", 2.75),  # 0.42 RPS
    "mistral-large-2512": _env_float("LLM_MIN_INTERVAL_MISTRAL_LARGE", 16.0),    # 0.07 RPS
    "magistral-medium-2509": 14.0,   # 0.08 RPS (reasoning model — slow tier)
    "ministral-8b-2512": 0.4,        # 3.13 RPS
    "ministral-3b-2512": 0.1,        # 12.50 RPS
}


def model_min_interval(provider_key: str, model_id: str) -> float:
    """Minimum seconds between two requests to the SAME model. Falls back to the
    provider-wide interval for models without a published per-model cap."""
    if model_id in MODEL_MIN_INTERVAL:
        return MODEL_MIN_INTERVAL[model_id]
    return provider_min_interval(provider_key)


# --- Hybrid capability classifier (Phase 1) ------------------------------------
# The LLM extraction pass runs at temperature 0 so identical finding text yields
# identical structured output (content-hash caching then makes re-runs free). A
# tight token budget keeps per-finding cost bounded; the response is one compact
# JSON object.
#
# On by default, but batched (CAPABILITY_LLM_BATCH_SIZE below): a full analyze
# costs only a few classification calls, not one-per-finding, so it stays under
# free-tier RPM caps. Set CAPABILITY_LLM_ENABLED=0 to force regex-only — the
# pipeline then behaves exactly as it did before Phase 1 (identical output, no
# token spend), the same graceful-degradation path taken when no provider exists.
CAPABILITY_LLM_ENABLED = os.environ.get("CAPABILITY_LLM_ENABLED", "1") != "0"
CAPABILITY_LLM_TEMPERATURE = _env_float("CAPABILITY_LLM_TEMPERATURE", 0.0)
CAPABILITY_LLM_MAX_TOKENS = _env_int("CAPABILITY_LLM_MAX_TOKENS", 700)
# Findings are classified in one batched call per group of this many (not one
# call each), so a full run costs a handful of calls rather than one-per-finding
# — the difference between sitting comfortably under a free-tier RPM cap and
# tripping it. Per-finding caching is unchanged; only cache-misses are batched.
CAPABILITY_LLM_BATCH_SIZE = _env_int("CAPABILITY_LLM_BATCH_SIZE", 12)


# --- Tool-using detection agent (Phase 3) --------------------------------------
# The Analyst Detection Agent runs a bounded ReAct loop over real graph+CMDB tools
# (list_entry_points, neighbors, finding_detail, test_hop, shortest_paths) instead
# of a single completion, so it investigates a path and verifies each hop before
# asserting it. Every iteration is ONE LLM round-trip; the tools execute locally
# (token-free). The loop is seeded with precomputed shortest-path candidates so the
# model usually finalizes in 2-3 turns, keeping a full run to a handful of calls —
# free-tier safe. Hard caps below bound cost absolutely (no unbounded loops).
#
# On by default; DETECTION_AGENT_ENABLED=0 falls back to the pre-Phase-3 single-shot
# reasoning (kept as a comparison / safety hatch). No provider ⇒ neither path spends
# a token: detection degrades to the deterministic engine exactly as before.
DETECTION_AGENT_ENABLED = os.environ.get("DETECTION_AGENT_ENABLED", "1") != "0"
DETECTION_AGENT_MAX_ITERS = _env_int("DETECTION_AGENT_MAX_ITERS", 8)      # LLM round-trips
DETECTION_AGENT_TOKEN_BUDGET = _env_int("DETECTION_AGENT_TOKEN_BUDGET", 24000)
DETECTION_AGENT_MAX_TOKENS = _env_int("DETECTION_AGENT_MAX_TOKENS", 2000)  # per call
DETECTION_AGENT_SHORTEST_K = _env_int("DETECTION_AGENT_SHORTEST_K", 3)     # seed candidates/target
DETECTION_AGENT_TEMPERATURE = _env_float("DETECTION_AGENT_TEMPERATURE", 0.0)
# Phase 4: the structured-CMDB query tools (reachability_rule / relationships_of /
# credentials_valid_on / business_service_of) read typed records on demand so the
# agent no longer depends on what fit in grounding_context's 7 KB truncation. Each
# tool caps its result list at this many rows so one call over a dense CMDB stays a
# small, bounded observation (the loop truncates observations anyway); a value that
# would drop rows is never silent — the tool flags `truncated: true`.
DETECTION_CMDB_TOOL_MAX_ROWS = _env_int("DETECTION_CMDB_TOOL_MAX_ROWS", 40)
# Cap on how many detected paths the agent emits (after score-ranking), so a
# chatty run can't flood the report; the highest-scoring grounded paths win.
DETECTION_MAX_EMITTED_PATHS = _env_int("DETECTION_MAX_EMITTED_PATHS", 8)


# --- Phase 4: graph-backed verification & calibrated path scoring ---------------
# The detection finalizer no longer silently drops any path with an unconfirmable
# hop. Instead every reconstructed path is assigned one of three labels:
#   grounded  — every hop is a REAL enabling graph edge forming a connected
#               INTERNET→target walk (soundness 1.0 by construction).
#   plausible — every host and cited QID resolves in scope, but >=1 hop the
#               reachability graph cannot confirm (a gap the analyst flags rather
#               than asserts). Never presented as grounded.
#   rejected  — no anchorable real host at all → not emitted (hallucination stays 0).
# A hop is `verified` iff a real edge exists AND its enabler is authoritative: an
# edge that carries a QID cites that QID; a QID-less lateral/adjacency edge is
# enabled by the relationship itself and may surface a cited QID only when that QID
# is a real finding on one of the two endpoint hosts (the tightening over Phase 3,
# which accepted any in-scope QID). A foreign QID is stripped, never presented.

# Calibrated path score = weighted sum of four inspectable components, each in
# [0,1]; the components are exposed alongside the scalar, not just the number:
#   reachability   — verified-hop ratio (real edges / total hops).
#   exploitability — strongest exploit signal across the path's cited findings:
#                    KEV>EPSS>CVSS when present in the data, else GRS/ACW (Phase-4
#                    open decision: in-dataset signals only, NO external feeds).
#   business_value — the target crown jewel's target_value (already blends zone
#                    criticality + DORA_CIF + exposure weight in the graph builder).
#   chain_length   — shorter chains score higher (ideal_hops / max(hops, ideal)).
# Weights, damping, and normalisers live here so nothing is a magic inline number.
PATH_SCORE_WEIGHTS: dict[str, float] = {
    "reachability": _env_float("PATH_W_REACHABILITY", 0.35),
    "exploitability": _env_float("PATH_W_EXPLOITABILITY", 0.25),
    "business_value": _env_float("PATH_W_BUSINESS", 0.30),
    "chain_length": _env_float("PATH_W_CHAIN", 0.10),
}
# A plausible path (>=1 unconfirmable hop) is damped by this factor after scoring so
# it can never outrank an equivalent fully-grounded path. In [0,1); <1 guarantees
# grounded > plausible at equal component values.
PATH_PLAUSIBLE_DAMPING = _env_float("PATH_PLAUSIBLE_DAMPING", 0.6)
# Chain-length component: a path of <= this many hops scores 1.0; each extra hop
# divides the score down (never to zero) so length is a gentle preference, not a veto.
PATH_CHAIN_IDEAL_HOPS = _env_int("PATH_CHAIN_IDEAL_HOPS", 2)
# GRS is an unbounded-ish risk score; normalise by this ceiling into [0,1] when it
# is the only exploit signal available. CVSS is normalised by 10.
PATH_GRS_CEILING = _env_float("PATH_GRS_CEILING", 100.0)


# --- Deterministic path ranker (Phase 2 discovery engine) -----------------------
# The autonomous path-discovery engine (core/attack_graph._score) ranks candidate
# INTERNET→crown paths by a weighted blend of the target's business value, the
# path's peak finding risk (GRS), lateral blast radius, and a mild penalty for
# longer chains. These are the DETERMINISTIC ranker's weights — distinct from the
# Phase-4 detection path score (PATH_SCORE_WEIGHTS above), which scores the AI
# agent's reconstructed paths. Defaults reproduce the pre-config ordering exactly
# (this is on the token-free deterministic path, so the committed eval baseline is
# unchanged); override via env only to re-tune the deterministic ranking.
DISC_SCORE_TARGET_VALUE_W = _env_float("DISC_SCORE_TARGET_VALUE_W", 45.0)
DISC_SCORE_GRS_W = _env_float("DISC_SCORE_GRS_W", 0.45)
DISC_SCORE_BLAST_W = _env_float("DISC_SCORE_BLAST_W", 8.0)
DISC_SCORE_LENGTH_PENALTY = _env_float("DISC_SCORE_LENGTH_PENALTY", 3.0)
DISC_SCORE_IDEAL_HOPS = _env_int("DISC_SCORE_IDEAL_HOPS", 2)  # no penalty at/below this


# --- Phase 3: authoritative reachability rule base → graph edges ----------------
# The CSV-backed CMDB's net_reachability.csv is THE authoritative zone-to-zone
# reachability table (docs/cmdb-accuracy-brief.md §2.1). attack_graph.build_graph
# turns each rule into real cross-zone edges instead of inferring crossings from
# VLAN numbering:
#   - a rule whose status is in REACHABILITY_TRAVERSABLE_STATUSES becomes a
#     directed edge (kind EDGE_KIND_REACHABILITY) from every host in the source
#     segment to every host in the destination segment, carrying its rule_id +
#     enabling_qid — so every cross-zone network hop is authoritative & auditable.
#   - a rule whose status is REACHABILITY_BLOCKED_STATUS ('Should-Not-Exist') is a
#     VETO: the (src_vlan, dst_vlan) pair is forbidden and NO edge of any kind
#     (reachability, inferred lateral/segmentation, credential, domain) may connect
#     those two zones, in either direction.
# These are the STATUS vocabulary from cmdb_ci_schema.ReachabilityStatus, surfaced
# here so the graph builder reads them from config rather than hardcoding strings.
# Markdown datasets have no reachability_edges, so this whole path no-ops for them
# and the legacy VLAN-number inference (capability.zone_transition) still applies.
REACHABILITY_TRAVERSABLE_STATUSES = {"Intended", "Excessive"}
REACHABILITY_BLOCKED_STATUS = "Should-Not-Exist"
EDGE_KIND_REACHABILITY = "reachability"


# --- Inbound API rate limiting --------------------------------------------------
# `/analyze` and `/chat` are the only endpoints that spend real LLM money (see
# core/ratelimit.py); everything else is a read of already-computed state. This
# is IP-keyed, not per-operator, since the app has no auth layer — see
# core/ratelimit.py's docstring for why that's a stopgap, not a real quota
# system. Defaults are sized for a single-operator lab tool (stop a runaway
# retry loop), not a public service. Tunable via env, same as the outbound
# LLM_* throttling above.
RATE_LIMIT_ANALYZE_PER_HOUR = _env_int("RATE_LIMIT_ANALYZE_PER_HOUR", 6)
RATE_LIMIT_CHAT_PER_MINUTE = _env_int("RATE_LIMIT_CHAT_PER_MINUTE", 10)

AGENT_ROLE_LABELS = {
    "capability": "Capability Extractor — reads each finding, extracts attacker capability",
    "correlation": "Correlation Agent — cross-references CMDB, assets, ownership",
    "attack_path": "Attack Path Agent — reconstructs & explains attack chains",
    "remediation": "Remediation Agent — enriches fixes beyond the scanner output",
    "compliance": "Compliance Agent — regulatory / framework reasoning",
    "triage": "Triage / Analyst Agent — executive synthesis & chat Q&A",
}


# --- Phase 2: environment-agnostic graph tiering --------------------------------
# The reachability graph derives its tiers from the CMDB's semantic trust levels,
# asset criticality labels, and platform strings — NOT from literal VLAN numbers —
# so detection generalises to any environment/numbering. Tokens below are matched
# case-insensitively as substrings of the CMDB values; override any via env
# (comma-separated) without touching the graph builder.
def _env_token_set(name: str, default: set[str]) -> set[str]:
    v = os.environ.get(name)
    return {x.strip().lower() for x in v.split(",") if x.strip()} if v else default


# Trust levels that make a zone attacker-reachable from outside (internet / guest).
ZONE_ENTRY_TRUST_TOKENS = _env_token_set(
    "GRAPH_ENTRY_TRUST", {"none", "untrusted", "internet-facing", "guest", "low"})
# Trust levels that mark a zone as a crown-jewel business zone (CDE/clinical/…).
# "critical (should be)" (management/OOB) is intentionally excluded — see predicate.
ZONE_CRITICAL_TRUST_TOKENS = _env_token_set("GRAPH_CRITICAL_TRUST", {"critical"})
# Trust markers for cloud/mixed zones (neither internal LAN nor a crown business zone).
ZONE_CLOUD_TRUST_TOKENS = _env_token_set("GRAPH_CLOUD_TRUST", {"mixed", "cloud"})
# Asset criticality labels the CMDB uses to flag a crown jewel outright.
CROWN_CRITICALITY_TOKENS = _env_token_set("GRAPH_CROWN_CRITICALITY", {"crown jewel"})
# Platform substrings that indicate an AD-joinable host (domain-admin blast radius).
AD_PLATFORM_TOKENS = _env_token_set("GRAPH_AD_PLATFORMS", {"windows"})
# ACW at/above which an asset is treated as a crown jewel on exposure weight alone.
CROWN_ACW_THRESHOLD = _env_float("GRAPH_CROWN_ACW", 0.88)


def zone_is_entry_exposed(trust: str) -> bool:
    t = str(trust).lower()
    return any(tok in t for tok in ZONE_ENTRY_TRUST_TOKENS)


def zone_is_critical(trust: str) -> bool:
    """A crown-jewel *business* zone. 'Critical (should be)' — the management/OOB
    zone whose finding is that it ISN'T isolated — is not itself a crown jewel."""
    t = str(trust).lower()
    return any(tok in t for tok in ZONE_CRITICAL_TRUST_TOKENS) and "should" not in t


def zone_is_cloud(trust: str) -> bool:
    return any(tok in str(trust).lower() for tok in ZONE_CLOUD_TRUST_TOKENS)


def zone_is_internal(trust: str) -> bool:
    """Internal LAN/critical/management zone — where AD-joined hosts live. Not
    internet/guest-exposed and not a cloud tenant."""
    return not zone_is_entry_exposed(trust) and not zone_is_cloud(trust)


def platform_is_ad_joined(role: str) -> bool:
    return any(tok in str(role).lower() for tok in AD_PLATFORM_TOKENS)


def criticality_is_crown(criticality: str) -> bool:
    return any(tok in str(criticality).lower() for tok in CROWN_CRITICALITY_TOKENS)


def get_api_key(provider_key: str, session_state) -> str | None:
    """Session-state key wins over environment (lets operators override per-session)."""
    spec = PROVIDERS[provider_key]
    val = session_state.get(f"apikey_{provider_key}") if session_state else None
    if val:
        return val
    return os.environ.get(spec.env_var)


def configured_providers(session_state) -> list[str]:
    return [p for p in PROVIDERS if get_api_key(p, session_state)]
