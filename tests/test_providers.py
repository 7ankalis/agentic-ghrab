import pytest
from pydantic import BaseModel

from vmc.providers.errors import ProviderError, ProviderErrorType
from vmc.providers.fake_provider import FakeProvider
from vmc.providers.repair import generate_json_with_repair
from vmc.providers.retry import AllProvidersExhausted, generate_json_with_fallback


class Echo(BaseModel):
    value: str


async def test_generate_json_with_repair_succeeds_first_try():
    calls = []

    async def call(system: str, prompt: str, temperature: float) -> str:
        calls.append(prompt)
        return '{"value": "ok"}'

    result = await generate_json_with_repair(
        call=call, system="sys", prompt="p", schema=Echo, temperature=0.1, provider_name="test"
    )
    assert result == Echo(value="ok")
    assert len(calls) == 1


async def test_generate_json_with_repair_recovers_on_second_attempt():
    responses = iter(["not json", '{"value": "fixed"}'])

    async def call(system: str, prompt: str, temperature: float) -> str:
        return next(responses)

    result = await generate_json_with_repair(
        call=call, system="sys", prompt="p", schema=Echo, temperature=0.1, provider_name="test"
    )
    assert result == Echo(value="fixed")


async def test_generate_json_with_repair_raises_after_two_failures():
    async def call(system: str, prompt: str, temperature: float) -> str:
        return "still not json"

    with pytest.raises(ProviderError) as exc_info:
        await generate_json_with_repair(
            call=call, system="sys", prompt="p", schema=Echo, temperature=0.1, provider_name="test"
        )
    assert exc_info.value.error_type == ProviderErrorType.INVALID_RESPONSE


async def test_fallback_moves_to_next_provider_on_auth_error():
    primary = FakeProvider(
        "primary", [ProviderError(ProviderErrorType.AUTH, "bad key", provider="primary")]
    )
    secondary = FakeProvider("secondary", [Echo(value="from secondary")])

    result = await generate_json_with_fallback(
        [primary, secondary], system="sys", prompt="p", schema=Echo
    )
    assert result == Echo(value="from secondary")
    assert primary.call_count == 1
    assert secondary.call_count == 1


async def test_fallback_retries_same_provider_on_rate_limit(monkeypatch):
    import vmc.providers.retry as retry_module

    monkeypatch.setattr(retry_module.asyncio, "sleep", _instant_sleep)

    primary = FakeProvider(
        "primary",
        [
            ProviderError(ProviderErrorType.RATE_LIMIT, "slow down", provider="primary"),
            Echo(value="from primary after backoff"),
        ],
    )
    result = await generate_json_with_fallback([primary], system="sys", prompt="p", schema=Echo)
    assert result == Echo(value="from primary after backoff")
    assert primary.call_count == 2


async def test_fallback_raises_when_required_and_all_exhausted(monkeypatch):
    import vmc.providers.retry as retry_module

    monkeypatch.setattr(retry_module.asyncio, "sleep", _instant_sleep)

    always_fails = FakeProvider(
        "flaky", [ProviderError(ProviderErrorType.RATE_LIMIT, "nope", provider="flaky")] * 4
    )
    with pytest.raises(AllProvidersExhausted):
        await generate_json_with_fallback([always_fails], system="sys", prompt="p", schema=Echo, required=True)


async def test_fallback_returns_none_when_optional_and_all_exhausted(monkeypatch):
    import vmc.providers.retry as retry_module

    monkeypatch.setattr(retry_module.asyncio, "sleep", _instant_sleep)

    always_fails = FakeProvider(
        "flaky", [ProviderError(ProviderErrorType.RATE_LIMIT, "nope", provider="flaky")] * 4
    )
    result = await generate_json_with_fallback(
        [always_fails], system="sys", prompt="p", schema=Echo, required=False
    )
    assert result is None


async def _instant_sleep(_seconds: float) -> None:
    return None
