"""The one-repair-retry contract for turning raw model text into a validated
Pydantic object (VMC_ARCHITECTURE_OVERVIEW.md §3.3, step 3).

Shared by every adapter so the "1 repair retry with the validation error
appended to the prompt" behavior is implemented exactly once.
"""

from __future__ import annotations

import json
import re
from typing import Awaitable, Callable

from pydantic import BaseModel, ValidationError

from vmc.providers.errors import ProviderError, ProviderErrorType
from vmc.providers.schema_prompt import build_repair_prompt

RawCall = Callable[[str, str, float], Awaitable[str]]  # (system, prompt, temperature) -> raw text


def _strip_markdown_fences(text: str) -> str:
    match = re.search(r"```(?:json)?\s*(.*?)\s*```", text, re.DOTALL)
    return match.group(1) if match else text


async def generate_json_with_repair(
    *,
    call: RawCall,
    system: str,
    prompt: str,
    schema: type[BaseModel],
    temperature: float,
    provider_name: str,
) -> BaseModel:
    raw = await call(system, prompt, temperature)
    try:
        return schema.model_validate_json(_strip_markdown_fences(raw))
    except (ValidationError, json.JSONDecodeError) as first_error:
        repair_prompt = build_repair_prompt(prompt, raw, str(first_error))
        raw_retry = await call(system, repair_prompt, temperature)
        try:
            return schema.model_validate_json(_strip_markdown_fences(raw_retry))
        except (ValidationError, json.JSONDecodeError) as second_error:
            raise ProviderError(
                ProviderErrorType.INVALID_RESPONSE,
                f"schema {schema.__name__} validation failed twice (after 1 repair retry): {second_error}",
                provider=provider_name,
                cause=second_error,
            ) from second_error
