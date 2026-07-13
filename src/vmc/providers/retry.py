"""The outer retry/back-off/fallback contract (VMC_ARCHITECTURE_OVERVIEW.md §3.3,
steps 4-5): exponential back-off on a provider error, then fall through the
`fallback_chain`; on total exhaustion, required agents abort, optional agents
degrade gracefully.

The per-call schema-repair retry (step 3) lives in `repair.py` and is already
baked into each adapter's `generate_json` — this module only deals with
provider-level failures (rate limit, auth, context-too-long, exhausted
repair) across a chain of providers.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from pydantic import BaseModel

from vmc.providers.base import LLMProvider, ToolSpec
from vmc.providers.errors import ProviderError, ProviderErrorType

logger = logging.getLogger("vmc.providers.retry")

BACKOFF_SCHEDULE_SECONDS = (1, 2, 4)

# Error types where retrying the *same* provider after a back-off is worth it.
# auth / context_too_long are not transient — move straight to the next
# provider in the fallback chain instead of burning the backoff schedule.
_RETRYABLE_ON_SAME_PROVIDER = {ProviderErrorType.RATE_LIMIT, ProviderErrorType.UNKNOWN}


class AllProvidersExhausted(ProviderError):
    def __init__(self, attempts: list[ProviderError]):
        providers = ", ".join(sorted({e.provider for e in attempts}))
        super().__init__(
            ProviderErrorType.UNKNOWN,
            f"all providers in fallback chain exhausted ({providers})",
            provider="fallback_chain",
        )
        self.attempts = attempts


async def generate_json_with_fallback(
    providers: list[LLMProvider],
    *,
    system: str,
    prompt: str,
    schema: type[BaseModel],
    temperature: float = 0.2,
    tools: list[ToolSpec] | None = None,
    required: bool = True,
) -> BaseModel | None:
    """Try `providers` in order, applying back-off within each and falling
    through to the next on exhaustion. Returns None only when `required` is
    False and every provider is exhausted (caller must log the degraded gap).
    """
    return await _run_with_fallback(
        providers,
        required=required,
        call=lambda provider: provider.generate_json(
            system=system, prompt=prompt, schema=schema, temperature=temperature, tools=tools
        ),
    )


async def generate_with_vision_and_fallback(
    providers: list[LLMProvider],
    *,
    system: str,
    prompt: str,
    images: list[bytes],
    schema: type[BaseModel],
    temperature: float = 0.2,
    required: bool = False,
) -> BaseModel | None:
    return await _run_with_fallback(
        providers,
        required=required,
        call=lambda provider: provider.generate_with_vision(
            system=system, prompt=prompt, images=images, schema=schema, temperature=temperature
        ),
    )


async def _run_with_fallback(providers: list[LLMProvider], *, required: bool, call: Any) -> BaseModel | None:
    if not providers:
        raise ValueError("providers list is empty — nothing to call")

    attempts: list[ProviderError] = []
    for provider in providers:
        for attempt_num, backoff_seconds in enumerate((0, *BACKOFF_SCHEDULE_SECONDS)):
            if backoff_seconds:
                await asyncio.sleep(backoff_seconds)
            try:
                return await call(provider)
            except ProviderError as err:
                attempts.append(err)
                logger.warning(
                    "provider %s failed (%s), attempt %d: %s",
                    provider.name,
                    err.error_type.value,
                    attempt_num + 1,
                    err,
                )
                if err.error_type not in _RETRYABLE_ON_SAME_PROVIDER:
                    break  # not transient — move to next provider immediately

    if required:
        raise AllProvidersExhausted(attempts)
    return None
