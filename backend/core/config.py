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

ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT_DIR / "data"
CACHE_DIR = DATA_DIR / "cache"
CACHE_DIR.mkdir(parents=True, exist_ok=True)

VULN_CSV_PATH = DATA_DIR / "ghrab_vulnerabilities_v2.csv"
ARCHITECTURE_MD_PATH = DATA_DIR / "ghrab_architecture_v2.md"
RISK_METHODOLOGY_MD_PATH = DATA_DIR / "ghrab_risk_methodology.md"
ANALYSIS_CACHE_PATH = CACHE_DIR / "analysis_cache.json"


# VULN_CSV_PATH = DATA_DIR / "velon_vulnerabilities.csv"
# ARCHITECTURE_MD_PATH = DATA_DIR / "velon_architecture.md"
# RISK_METHODOLOGY_MD_PATH = DATA_DIR / "ghrab_risk_methodology.md"
# ANALYSIS_CACHE_PATH = CACHE_DIR / "analysis_cache.json"

# Per-org framing for the LLM analyst persona (agents/base.py) — keyed off which
# lab's CSV is currently active so agent narratives describe the right sector
# and compliance frameworks instead of always assuming Ghrab Financial Group.
ORG_PROFILES: dict[str, dict[str, str]] = {
    "ghrab": {
        "name": "Ghrab Financial Group",
        "sector": "a financial services firm",
        "frameworks": "PCI DSS, SWIFT CSP, EU DORA",
    },
    "velon": {
        "name": "Velon Health Systems",
        "sector": "a healthcare provider",
        "frameworks": "HIPAA Security Rule, FDA Premarket/Postmarket Cybersecurity Guidance",
    },
}
ACTIVE_ORG = ORG_PROFILES[VULN_CSV_PATH.stem.split("_")[0]]

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
    "correlation": "groq",       # fast, high-volume cross-referencing
    "attack_path": "mistral",    # large-context reasoning for chain analysis
    "remediation": "groq",
    "compliance": "mistral",
    "triage": "mistral",         # executive synthesis + analyst chat
}

FALLBACK_ORDER = ["mistral", "groq", "gemini", "anthropic", "openai", "deepseek", "xai"]

# --- Client-side rate limiting -------------------------------------------------
# Free provider tiers cap requests-per-minute (Gemini flash ~15 RPM, Mistral free
# ~1 RPS, Groq ~30 RPM). A full pipeline run fires ~6 calls back-to-back, which
# trips those caps instantly. We therefore (a) space consecutive calls to the
# SAME provider by a minimum interval, and (b) on a 429 we back off and retry the
# same provider instead of immediately burning through the fallback chain (whose
# providers are just as rate-limited). All tunable via env without a code change.
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


def provider_min_interval(provider_key: str) -> float:
    return PROVIDER_MIN_INTERVAL.get(provider_key, LLM_MIN_INTERVAL_SEC)

AGENT_ROLE_LABELS = {
    "correlation": "Correlation Agent — cross-references CMDB, assets, ownership",
    "attack_path": "Attack Path Agent — reconstructs & explains attack chains",
    "remediation": "Remediation Agent — enriches fixes beyond the scanner output",
    "compliance": "Compliance Agent — regulatory / framework reasoning",
    "triage": "Triage / Analyst Agent — executive synthesis & chat Q&A",
}


def get_api_key(provider_key: str, session_state) -> str | None:
    """Session-state key wins over environment (lets operators override per-session)."""
    spec = PROVIDERS[provider_key]
    val = session_state.get(f"apikey_{provider_key}") if session_state else None
    if val:
        return val
    return os.environ.get(spec.env_var)


def configured_providers(session_state) -> list[str]:
    return [p for p in PROVIDERS if get_api_key(p, session_state)]
