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

VULN_CSV_PATH = DATA_DIR / "ghrab_vulnerabilities.csv"
ARCHITECTURE_MD_PATH = DATA_DIR / "ghrab_architecture.md"
RISK_METHODOLOGY_MD_PATH = DATA_DIR / "ghrab_risk_methodology.md"
ANALYSIS_CACHE_PATH = CACHE_DIR / "analysis_cache.json"


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
