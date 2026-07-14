"""DeepSeek adapter. DeepSeek's API is OpenAI-compatible, so this reuses the
`openai` SDK (already a dependency for `OpenAIProvider`) pointed at
DeepSeek's base URL instead of a separate vendor SDK — same pattern as
pointing any OpenAI-compatible gateway (Azure OpenAI, vLLM, etc.) at a
different `base_url`.

Uses native JSON mode via `response_format`, same as `OpenAIProvider`; the
shared repair loop is still the safety net for prompts that don't honor it
strictly. Deliberately does not enable DeepSeek's "thinking" mode
(`extra_body={"thinking": {"type": "enabled"}}`) — every call through this
adapter is a strict structured-output call (`generate_json`), and reasoning
traces aren't useful when the only thing that matters is valid JSON matching
`schema`.
"""

from __future__ import annotations

from pydantic import BaseModel

from vmc.providers.base import ToolSpec
from vmc.providers.errors import ProviderError, ProviderErrorType
from vmc.providers.repair import generate_json_with_repair
from vmc.providers.schema_prompt import build_json_system_prompt

_DEEPSEEK_BASE_URL = "https://api.deepseek.com"


class DeepSeekProvider:
    name = "deepseek"

    def __init__(self, model: str | None = None, temperature: float = 0.2, *, api_key: str | None = None):
        self.model = model or "deepseek-v4-pro"
        self.default_temperature = temperature
        self._api_key = api_key
        self._client = None

    def _ensure_client(self):
        if self._client is not None:
            return self._client
        try:
            from openai import AsyncOpenAI
        except ImportError as exc:
            raise ProviderError(
                ProviderErrorType.UNKNOWN,
                "openai is not installed (pip install vmc[openai]) — DeepSeek reuses the OpenAI SDK "
                "against DeepSeek's own base_url",
                provider=self.name,
                cause=exc,
            ) from exc
        self._client = AsyncOpenAI(api_key=self._api_key, base_url=_DEEPSEEK_BASE_URL)
        return self._client

    async def _raw_generate(self, system: str, prompt: str, temperature: float) -> str:
        client = self._ensure_client()
        try:
            response = await client.chat.completions.create(
                model=self.model,
                temperature=temperature,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
            )
            return response.choices[0].message.content
        except Exception as exc:  # noqa: BLE001 - normalized below
            raise _normalize_deepseek_error(exc, self.name) from exc

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
            "DeepSeekProvider has no vision model configured; route vision calls to gemini or anthropic",
            provider=self.name,
        )


def _normalize_deepseek_error(exc: Exception, provider_name: str) -> ProviderError:
    status = getattr(exc, "status_code", None)
    message = str(exc).lower()
    if status == 429 or "rate" in message or "insufficient balance" in message:
        error_type = ProviderErrorType.RATE_LIMIT
    elif status in (401, 403) or "api key" in message or "auth" in message:
        error_type = ProviderErrorType.AUTH
    elif "context" in message and "length" in message:
        error_type = ProviderErrorType.CONTEXT_TOO_LONG
    else:
        error_type = ProviderErrorType.UNKNOWN
    return ProviderError(error_type, str(exc), provider=provider_name, cause=exc)
