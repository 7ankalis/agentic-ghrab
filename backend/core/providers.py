"""
Unified LLM calling layer built on litellm, with automatic provider fallback.

An agent asks for a *role* (e.g. "attack_path"), not a specific vendor. This
module resolves that role to a provider using the operator's preferences
(session_state), skips providers with no configured key, and falls back
through FALLBACK_ORDER if the preferred provider fails or has no key.
If literally no key is configured anywhere, callers get a clear
ProviderUnavailable so the UI can degrade gracefully to deterministic-only mode.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass

from core.config import (
    AGENT_ROLES,
    DEFAULT_AGENT_PROVIDER,
    FALLBACK_ORDER,
    PROVIDERS,
    get_api_key,
)

logger = logging.getLogger(__name__)


class ProviderUnavailable(Exception):
    pass


@dataclass
class LLMResult:
    text: str
    provider: str
    model: str


def _agent_provider_order(role: str, session_state) -> list[str]:
    preferred = session_state.get(f"agent_provider_{role}") if session_state else None
    preferred = preferred or DEFAULT_AGENT_PROVIDER.get(role, FALLBACK_ORDER[0])
    order = [preferred] + [p for p in FALLBACK_ORDER if p != preferred]
    return order


def any_provider_configured(session_state) -> bool:
    return any(get_api_key(p, session_state) for p in PROVIDERS)


def call_llm(
    role: str,
    system_prompt: str,
    user_prompt: str,
    session_state=None,
    json_mode: bool = False,
    max_tokens: int = 2000,
    temperature: float = 0.2,
) -> LLMResult:
    """Call the LLM assigned to `role`, trying providers in preference/fallback order."""
    import litellm  # imported lazily so the app can run with litellm absent until needed

    litellm.suppress_debug_info = True
    order = _agent_provider_order(role, session_state)
    last_err: Exception | None = None

    for provider_key in order:
        api_key = get_api_key(provider_key, session_state)
        if not api_key:
            continue
        spec = PROVIDERS[provider_key]
        model_override = (session_state.get(f"agent_model_{role}") if session_state else None)
        model_id = model_override or spec.default_model
        litellm_model = f"{spec.litellm_prefix}/{model_id}" if spec.litellm_prefix else model_id
        try:
            kwargs = dict(
                model=litellm_model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                api_key=api_key,
                max_tokens=max_tokens,
                temperature=temperature,
            )
            if json_mode:
                kwargs["response_format"] = {"type": "json_object"}
            resp = litellm.completion(**kwargs)
            text = resp["choices"][0]["message"]["content"]
            return LLMResult(text=text, provider=provider_key, model=model_id)
        except Exception as exc:  # noqa: BLE001 - deliberately broad, we fall back
            logger.warning("Provider %s failed for role %s: %s", provider_key, role, exc)
            last_err = exc
            continue

    raise ProviderUnavailable(
        f"No configured provider could serve role '{role}'. "
        f"Add an API key in Settings. Last error: {last_err}"
    )


def call_llm_json(role: str, system_prompt: str, user_prompt: str, session_state=None,
                   max_tokens: int = 2000) -> dict:
    result = call_llm(role, system_prompt, user_prompt, session_state,
                       json_mode=True, max_tokens=max_tokens)
    text = result.text.strip()
    # some providers wrap JSON in ```json fences despite response_format
    if text.startswith("```"):
        text = text.strip("`")
        if text.startswith("json"):
            text = text[4:]
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start != -1 and end != -1:
            return json.loads(text[start:end + 1])
        raise
