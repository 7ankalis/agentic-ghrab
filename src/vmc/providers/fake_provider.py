"""In-memory LLMProvider used by tests and offline dev — no SDK, no network.

Scripted with a queue of canned responses/exceptions so the shared retry/
repair/fallback contract can be exercised deterministically.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from vmc.providers.base import ToolSpec
from vmc.providers.errors import ProviderError


class FakeProvider:
    def __init__(self, name: str, responses: list[Any]):
        """`responses` items are either a `BaseModel` instance to return, or a
        `ProviderError` instance to raise, consumed in order per call."""
        self.name = name
        self._responses = list(responses)
        self.call_count = 0

    async def generate_json(
        self,
        *,
        system: str,
        prompt: str,
        schema: type[BaseModel],
        temperature: float = 0.2,
        tools: list[ToolSpec] | None = None,
    ) -> BaseModel:
        self.call_count += 1
        if not self._responses:
            raise AssertionError(f"FakeProvider[{self.name}] ran out of scripted responses")
        item = self._responses.pop(0)
        if isinstance(item, ProviderError):
            raise item
        return item

    async def generate_with_vision(
        self,
        *,
        system: str,
        prompt: str,
        images: list[bytes],
        schema: type[BaseModel],
        temperature: float = 0.2,
    ) -> BaseModel:
        return await self.generate_json(system=system, prompt=prompt, schema=schema, temperature=temperature)
