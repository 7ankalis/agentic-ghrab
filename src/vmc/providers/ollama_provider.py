"""Ollama adapter — the offline/air-gapped fallback of last resort in every
agent's `fallback_chain`. No vendor SDK: Ollama exposes a local REST API, so
this talks to it directly over `httpx` (a base dependency, not optional,
since this is the one provider every deployment can always fall back to).
No API key is ever required — a local Ollama daemon is either reachable or
it isn't.
"""

from __future__ import annotations

import httpx
from pydantic import BaseModel

from vmc.providers.base import ToolSpec
from vmc.providers.errors import ProviderError, ProviderErrorType
from vmc.providers.repair import generate_json_with_repair
from vmc.providers.schema_prompt import build_json_system_prompt

_DEFAULT_HOST = "http://localhost:11434"
_REQUEST_TIMEOUT_SECONDS = 60.0


class OllamaProvider:
    name = "ollama"

    def __init__(self, model: str | None = None, temperature: float = 0.2, *, host: str = _DEFAULT_HOST):
        self.model = model or "llama3.1"
        self.default_temperature = temperature
        self._host = host.rstrip("/")

    async def _raw_generate(self, system: str, prompt: str, temperature: float) -> str:
        try:
            async with httpx.AsyncClient(timeout=_REQUEST_TIMEOUT_SECONDS) as client:
                response = await client.post(
                    f"{self._host}/api/chat",
                    json={
                        "model": self.model,
                        "format": "json",
                        "stream": False,
                        "options": {"temperature": temperature},
                        "messages": [
                            {"role": "system", "content": system},
                            {"role": "user", "content": prompt},
                        ],
                    },
                )
                response.raise_for_status()
                return response.json()["message"]["content"]
        except Exception as exc:  # noqa: BLE001 - normalized below
            raise _normalize_ollama_error(exc, self.name) from exc

    async def generate_json(
        self,
        *,
        system: str,
        prompt: str,
        schema: type[BaseModel],
        temperature: float = 0.2,
        tools: list[ToolSpec] | None = None,
    ) -> BaseModel:
        json_system = build_json_system_prompt(system, schema)
        return await generate_json_with_repair(
            call=self._raw_generate,
            system=json_system,
            prompt=prompt,
            schema=schema,
            temperature=temperature,
            provider_name=self.name,
        )

    async def generate_with_vision(
        self,
        *,
        system: str,
        prompt: str,
        images: list[bytes],
        schema: type[BaseModel],
        temperature: float = 0.2,
    ) -> BaseModel:
        raise ProviderError(
            ProviderErrorType.UNKNOWN,
            "OllamaProvider has no vision model configured by default; route vision calls to gemini or anthropic",
            provider=self.name,
        )


def _normalize_ollama_error(exc: Exception, provider_name: str) -> ProviderError:
    if isinstance(exc, httpx.ConnectError):
        return ProviderError(
            ProviderErrorType.UNKNOWN, f"ollama daemon unreachable at host: {exc}", provider=provider_name, cause=exc
        )
    status = getattr(getattr(exc, "response", None), "status_code", None)
    message = str(exc).lower()
    if status == 429 or "rate" in message:
        error_type = ProviderErrorType.RATE_LIMIT
    elif status in (401, 403) or "auth" in message:
        error_type = ProviderErrorType.AUTH
    elif "context" in message and "length" in message:
        error_type = ProviderErrorType.CONTEXT_TOO_LONG
    else:
        error_type = ProviderErrorType.UNKNOWN
    return ProviderError(error_type, str(exc), provider=provider_name, cause=exc)
