"""Anthropic adapter. Claude has no native "JSON mode" toggle, so every call
goes through the shared prompt-enforced-JSON + repair loop. Vision is a real
capability here (base64 image blocks), used as the fallback vision path when
Gemini is unavailable.
"""

from __future__ import annotations

import base64

from pydantic import BaseModel

from vmc.providers.base import ToolSpec
from vmc.providers.errors import ProviderError, ProviderErrorType
from vmc.providers.repair import generate_json_with_repair
from vmc.providers.schema_prompt import build_json_system_prompt

_MAX_OUTPUT_TOKENS = 4096


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, model: str | None = None, temperature: float = 0.2, *, api_key: str | None = None):
        self.model = model or "claude-sonnet-4-6"
        self.default_temperature = temperature
        self._api_key = api_key
        self._client = None

    def _ensure_client(self):
        if self._client is not None:
            return self._client
        try:
            from anthropic import AsyncAnthropic
        except ImportError as exc:
            raise ProviderError(
                ProviderErrorType.UNKNOWN,
                "anthropic is not installed (pip install vmc[anthropic])",
                provider=self.name,
                cause=exc,
            ) from exc
        self._client = AsyncAnthropic(api_key=self._api_key)
        return self._client

    async def _raw_generate(self, system: str, prompt: str, temperature: float) -> str:
        client = self._ensure_client()
        try:
            response = await client.messages.create(
                model=self.model,
                system=system,
                max_tokens=_MAX_OUTPUT_TOKENS,
                temperature=temperature,
                messages=[{"role": "user", "content": prompt}],
            )
            return "".join(block.text for block in response.content if block.type == "text")
        except Exception as exc:  # noqa: BLE001 - normalized below
            raise _normalize_anthropic_error(exc, self.name) from exc

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
        client = self._ensure_client()
        json_system = build_json_system_prompt(system, schema)

        async def _raw_vision_generate(sys_prompt: str, user_prompt: str, temp: float) -> str:
            image_blocks = [
                {
                    "type": "image",
                    "source": {"type": "base64", "media_type": "image/png", "data": base64.b64encode(img).decode()},
                }
                for img in images
            ]
            try:
                response = await client.messages.create(
                    model=self.model,
                    system=sys_prompt,
                    max_tokens=_MAX_OUTPUT_TOKENS,
                    temperature=temp,
                    messages=[{"role": "user", "content": [*image_blocks, {"type": "text", "text": user_prompt}]}],
                )
                return "".join(block.text for block in response.content if block.type == "text")
            except Exception as exc:  # noqa: BLE001
                raise _normalize_anthropic_error(exc, self.name) from exc

        return await generate_json_with_repair(
            call=_raw_vision_generate,
            system=json_system,
            prompt=prompt,
            schema=schema,
            temperature=temperature,
            provider_name=self.name,
        )


def _normalize_anthropic_error(exc: Exception, provider_name: str) -> ProviderError:
    status = getattr(exc, "status_code", None)
    message = str(exc).lower()
    if status == 429 or "rate" in message:
        error_type = ProviderErrorType.RATE_LIMIT
    elif status in (401, 403) or "api key" in message or "auth" in message:
        error_type = ProviderErrorType.AUTH
    elif "context" in message and ("too long" in message or "token" in message):
        error_type = ProviderErrorType.CONTEXT_TOO_LONG
    else:
        error_type = ProviderErrorType.UNKNOWN
    return ProviderError(error_type, str(exc), provider=provider_name, cause=exc)
