"""The `LLMProvider` protocol — the one interface every agent talks to.

No agent, orchestrator, or router code should ever import a vendor SDK
directly. Concrete adapters (GeminiProvider, GroqProvider, ...) implement
this protocol and are the only place a vendor SDK is imported.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Protocol

from pydantic import BaseModel


@dataclass(frozen=True)
class ToolSpec:
    """A tool Agent 3 (or any future tool-calling agent) can offer to a model.

    Written once as a plain async function; each provider adapter maps this
    into that vendor's function-calling format.
    """

    name: str
    description: str
    parameters_schema: dict[str, Any]  # JSON schema for the tool's arguments
    handler: Callable[..., Awaitable[Any]]


class LLMProvider(Protocol):
    """Provider-agnostic entry point for structured generation.

    Adapters are responsible for:
    - translating `schema` into that provider's structured-output/JSON-mode
      mechanism (native JSON mode where available, else a strict
      "return only JSON matching this schema" system prompt + repair retry)
    - translating `tools` into that provider's function-calling format
    - normalizing errors into `ProviderError` (see errors.py) so retry/
      back-off logic never needs to know which vendor failed
    """

    name: str  # e.g. "gemini", "groq" — used in ModelRouter policy + logs

    async def generate_json(
        self,
        *,
        system: str,
        prompt: str,
        schema: type[BaseModel],
        temperature: float = 0.2,
        tools: list[ToolSpec] | None = None,
    ) -> BaseModel: ...

    async def generate_with_vision(
        self,
        *,
        system: str,
        prompt: str,
        images: list[bytes],
        schema: type[BaseModel],
        temperature: float = 0.2,
    ) -> BaseModel: ...
