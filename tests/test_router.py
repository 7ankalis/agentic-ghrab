import pytest

from vmc.providers.router import ModelRouter


class DummyProvider:
    def __init__(self, name: str, model: str | None, temperature: float):
        self.name = name
        self.model = model
        self.temperature = temperature


POLICY = {
    "agents": {
        "threat_intel_enrichment": {"provider": "groq", "model": "llama-3.3-70b", "temperature": 0.1},
        "attack_path_discovery": {"provider": "gemini", "model": "gemini-2.5-pro", "temperature": 0.4},
    },
    "fallback_chain": ["gemini", "anthropic", "groq", "ollama"],
}


def _registry():
    return {
        "groq": lambda model, temp: DummyProvider("groq", model, temp),
        "gemini": lambda model, temp: DummyProvider("gemini", model, temp),
        # anthropic and ollama intentionally not registered (no API key configured)
    }


def test_policy_for_returns_configured_agent():
    router = ModelRouter(POLICY, _registry())
    policy = router.policy_for("threat_intel_enrichment")
    assert policy.provider == "groq"
    assert policy.model == "llama-3.3-70b"
    assert policy.temperature == 0.1


def test_policy_for_unknown_agent_raises():
    router = ModelRouter(POLICY, _registry())
    with pytest.raises(KeyError):
        router.policy_for("nonexistent_agent")


def test_providers_for_orders_primary_first_then_fallback_chain_skipping_missing():
    router = ModelRouter(POLICY, _registry())
    providers = router.providers_for("threat_intel_enrichment")

    # primary is groq; fallback_chain is [gemini, anthropic(missing), groq(dup, skipped), ollama(missing)]
    assert [p.name for p in providers] == ["groq", "gemini"]
    assert providers[0].model == "llama-3.3-70b"  # primary keeps its configured model
    assert providers[1].model is None  # fallback provider uses its own default model


def test_providers_for_raises_if_nothing_usable():
    registry = {}  # nothing registered at all
    router = ModelRouter(POLICY, registry)
    with pytest.raises(KeyError):
        router.providers_for("threat_intel_enrichment")
