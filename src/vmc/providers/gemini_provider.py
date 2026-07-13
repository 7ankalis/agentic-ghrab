"""Gemini adapter. Uses Gemini's native JSON mode when available, with the
shared repair loop as a safety net, and is the vision-capable adapter used
for Agent 2's diagram-vs-markdown cross-check.

The `google-generativeai` SDK is imported lazily so the rest of the codebase
never fails to import just because this optional dependency isn't installed.
"""

from __future__ import annotations

from pydantic import BaseModel

from vmc.providers.base import ToolSpec
from vmc.providers.errors import ProviderError, ProviderErrorType
from vmc.providers.repair import generate_json_with_repair
from vmc.providers.schema_prompt import build_json_system_prompt


class GeminiProvider:
    name = "gemini"

    def __init__(self, model: str | None = None, temperature: float = 0.2, *, api_key: str | None = None):
        self.model = model or "gemini-2.5-pro"
        self.default_temperature = temperature
        self._api_key = api_key
        self._client = None  # lazily constructed on first call

    def _ensure_client(self):
        if self._client is not None:
            return self._client
        try:
            import google.generativeai as genai
        except ImportError as exc:
            raise ProviderError(
                ProviderErrorType.UNKNOWN,
                "google-generativeai is not installed (pip install vmc[gemini])",
                provider=self.name,
                cause=exc,
            ) from exc
        if self._api_key:
            genai.configure(api_key=self._api_key)
        self._client = genai
        return self._client

    async def _raw_generate(self, system: str, prompt: str, temperature: float) -> str:
        genai = self._ensure_client()
        try:
            model = genai.GenerativeModel(self.model, system_instruction=system)
            response = await model.generate_content_async(
                prompt,
                generation_config={"temperature": temperature, "response_mime_type": "application/json"},
            )
            return response.text
        except Exception as exc:  # noqa: BLE001 - normalized below
            raise _normalize_gemini_error(exc, self.name) from exc

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
        genai = self._ensure_client()
        json_system = build_json_system_prompt(system, schema)

        async def _raw_vision_generate(sys_prompt: str, user_prompt: str, temp: float) -> str:
            try:
                model = genai.GenerativeModel(self.model, system_instruction=sys_prompt)
                parts = [{"mime_type": "image/png", "data": img} for img in images] + [user_prompt]
                response = await model.generate_content_async(
                    parts,
                    generation_config={"temperature": temp, "response_mime_type": "application/json"},
                )
                return response.text
            except Exception as exc:  # noqa: BLE001
                raise _normalize_gemini_error(exc, self.name) from exc

        return await generate_json_with_repair(
            call=_raw_vision_generate,
            system=json_system,
            prompt=prompt,
            schema=schema,
            temperature=temperature,
            provider_name=self.name,
        )


def _normalize_gemini_error(exc: Exception, provider_name: str) -> ProviderError:
    message = str(exc).lower()
    if "429" in message or "rate" in message or "quota" in message:
        error_type = ProviderErrorType.RATE_LIMIT
    elif "401" in message or "403" in message or "api key" in message or "permission" in message:
        error_type = ProviderErrorType.AUTH
    elif "context" in message and ("too long" in message or "token" in message):
        error_type = ProviderErrorType.CONTEXT_TOO_LONG
    else:
        error_type = ProviderErrorType.UNKNOWN
    return ProviderError(error_type, str(exc), provider=provider_name, cause=exc)
