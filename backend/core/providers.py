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
import threading
import time
import uuid
from dataclasses import dataclass

from core import call_log
from core.config import (
    AGENT_ROLES,
    DEFAULT_AGENT_MODEL,
    DEFAULT_AGENT_PROVIDER,
    FALLBACK_ORDER,
    LLM_BACKOFF_BASE_SEC,
    LLM_BACKOFF_MAX_SEC,
    LLM_MAX_RETRIES,
    LLM_REQUEST_TIMEOUT_SEC,
    PROVIDERS,
    get_api_key,
    model_min_interval,
    provider_min_interval,
)

logger = logging.getLogger(__name__)


class ProviderUnavailable(Exception):
    pass


# --- Client-side rate limiting -------------------------------------------------
# call_llm() runs on background threads (SSE handlers, the pipeline), so the
# per-provider spacing has to be thread-safe. Holding the provider's lock across
# the sleep serialises concurrent same-provider calls, which is exactly the
# throttle we want; different providers never block each other.
_provider_locks: dict[str, threading.Lock] = {}
_provider_last_call: dict[str, float] = {}
_locks_guard = threading.Lock()


def _provider_lock(provider_key: str) -> threading.Lock:
    with _locks_guard:
        lock = _provider_locks.get(provider_key)
        if lock is None:
            lock = threading.Lock()
            _provider_locks[provider_key] = lock
        return lock


def _throttle(provider_key: str, model_id: str) -> None:
    """Block until at least `model_min_interval` seconds have elapsed since the
    last request to this SAME (provider, model). Keyed per model because free-tier
    RPS caps are per model — a fast model must not be paced to a slow one's rate,
    nor a slow one under-throttled into 429s."""
    interval = model_min_interval(provider_key, model_id)
    if interval <= 0:
        return
    throttle_key = f"{provider_key}:{model_id}"
    with _provider_lock(throttle_key):
        now = time.monotonic()
        wait = interval - (now - _provider_last_call.get(throttle_key, 0.0))
        if wait > 0:
            logger.info("Throttling %s: waiting %.1fs before next request", throttle_key, wait)
            time.sleep(wait)
        _provider_last_call[throttle_key] = time.monotonic()


def _is_rate_limit(exc: Exception) -> bool:
    status = getattr(exc, "status_code", None) or getattr(exc, "code", None)
    if status == 429:
        return True
    name = exc.__class__.__name__.lower()
    return "ratelimit" in name or "429" in str(exc) or "rate limit" in str(exc).lower()


def _is_timeout(exc: Exception) -> bool:
    """A request timeout (litellm.Timeout / httpx / socket) — retry the same
    provider before falling through, like a 429: a transient stall, not a hard
    failure of the model or key."""
    name = exc.__class__.__name__.lower()
    return "timeout" in name or "timed out" in str(exc).lower()


def _retry_after_seconds(exc: Exception, attempt: int) -> float:
    """Prefer the provider's Retry-After header; else exponential backoff."""
    headers = getattr(exc, "response", None)
    headers = getattr(headers, "headers", None) or getattr(exc, "headers", None)
    if headers:
        for key in ("retry-after", "Retry-After", "x-ratelimit-reset"):
            val = headers.get(key) if hasattr(headers, "get") else None
            if val:
                try:
                    return min(float(val), LLM_BACKOFF_MAX_SEC)
                except (TypeError, ValueError):
                    pass
    return min(LLM_BACKOFF_BASE_SEC * (2 ** attempt), LLM_BACKOFF_MAX_SEC)


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
    detail: str = "",
) -> LLMResult:
    """Call the LLM assigned to `role`, trying providers in preference/fallback order.

    Every attempt — including ones that fail and fall through — is recorded in
    core.call_log so the Agent Activity panel can show, live, which agent is
    calling which provider and why a fallback happened."""
    import litellm  # imported lazily so the app can run with litellm absent until needed

    litellm.suppress_debug_info = True
    order = _agent_provider_order(role, session_state)
    last_err: Exception | None = None
    group_id = uuid.uuid4().hex[:8]
    overall_attempt = 0

    for provider_key in order:
        api_key = get_api_key(provider_key, session_state)
        if not api_key:
            continue
        spec = PROVIDERS[provider_key]
        model_override = (session_state.get(f"agent_model_{role}") if session_state else None)
        # The curated per-role model applies only on the role's preferred provider
        # (its id is provider-specific); a fallback provider uses its own default.
        role_default = (DEFAULT_AGENT_MODEL.get(role)
                        if provider_key == DEFAULT_AGENT_PROVIDER.get(role) else None)
        model_id = model_override or role_default or spec.default_model
        litellm_model = f"{spec.litellm_prefix}/{model_id}" if spec.litellm_prefix else model_id

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
        # Bound how long a single attempt may hang; 0 leaves it to the client default.
        if LLM_REQUEST_TIMEOUT_SEC > 0:
            kwargs["timeout"] = LLM_REQUEST_TIMEOUT_SEC
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}

        # Retry the SAME provider on rate limits (429) with backoff before falling
        # through — the next provider is on an equally small free tier, so burning
        # straight through the chain just spreads the 429s around.
        for attempt in range(LLM_MAX_RETRIES + 1):
            overall_attempt += 1
            _throttle(provider_key, model_id)
            call_id = call_log.start(role, provider_key, model_id, detail,
                                      attempt=overall_attempt, group_id=group_id)
            t0 = time.monotonic()
            try:
                resp = litellm.completion(**kwargs)
                text = resp["choices"][0]["message"]["content"]
                tokens, prompt_tokens, completion_tokens = _extract_tokens(resp)
                cost_usd = _extract_cost(resp)
                call_log.finish(call_id, role, provider_key, model_id, True,
                                (time.monotonic() - t0) * 1000, tokens=tokens,
                                prompt_tokens=prompt_tokens, completion_tokens=completion_tokens,
                                cost_usd=cost_usd, detail=detail,
                                attempt=overall_attempt, group_id=group_id)
                return LLMResult(text=text, provider=provider_key, model=model_id)
            except Exception as exc:  # noqa: BLE001 - deliberately broad, we retry / fall back
                call_log.finish(call_id, role, provider_key, model_id, False,
                                (time.monotonic() - t0) * 1000, error=str(exc)[:800], detail=detail,
                                attempt=overall_attempt, group_id=group_id)
                last_err = exc
                if (_is_rate_limit(exc) or _is_timeout(exc)) and attempt < LLM_MAX_RETRIES:
                    reason = "rate-limited" if _is_rate_limit(exc) else "timed out"
                    delay = _retry_after_seconds(exc, attempt)
                    logger.warning("Provider %s %s for role %s (attempt %d/%d); "
                                   "backing off %.1fs", provider_key, reason, role, attempt + 1,
                                   LLM_MAX_RETRIES, delay)
                    time.sleep(delay)
                    continue
                logger.warning("Provider %s failed for role %s: %s", provider_key, role, exc)
                break  # non-retryable error, or retries exhausted → next provider

    raise ProviderUnavailable(
        f"No configured provider could serve role '{role}'. "
        f"Add an API key in Settings. Last error: {last_err}"
    )


def _extract_tokens(resp) -> tuple[int | None, int | None, int | None]:
    """Returns (total, prompt, completion) tokens, each best-effort."""
    try:
        usage = resp["usage"]
        get = usage.get if isinstance(usage, dict) else lambda k: getattr(usage, k, None)
        return get("total_tokens"), get("prompt_tokens"), get("completion_tokens")
    except Exception:  # noqa: BLE001 — best-effort only, never breaks the call
        return None, None, None


def _extract_cost(resp) -> float | None:
    """Best-effort USD cost via litellm's pricing table; silently absent for
    models/providers litellm has no pricing data for."""
    try:
        import litellm
        cost = litellm.completion_cost(completion_response=resp)
        return round(cost, 6) if cost else None
    except Exception:  # noqa: BLE001 — pricing lookups are best-effort only
        return None


def call_llm_json(role: str, system_prompt: str, user_prompt: str, session_state=None,
                   max_tokens: int = 2000, detail: str = "", temperature: float = 0.2) -> dict:
    result = call_llm(role, system_prompt, user_prompt, session_state,
                       json_mode=True, max_tokens=max_tokens, temperature=temperature,
                       detail=detail)
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
