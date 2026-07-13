"""`ModelRouter` — per-agent, per-tenant model selection (§3.2).

Reads a YAML policy mapping agent_name -> {provider, model, temperature} plus
a `fallback_chain`. Swapping a provider for one agent is a config change, not
a code change: nothing in this module imports a vendor SDK — provider
instances are built lazily via a caller-supplied registry of factories.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import yaml

from vmc.providers.base import LLMProvider

ProviderFactory = Callable[[str | None, float], LLMProvider]  # (model, temperature) -> LLMProvider instance


@dataclass(frozen=True)
class AgentModelPolicy:
    agent_name: str
    provider: str
    model: str
    temperature: float


class ModelRouter:
    def __init__(self, policy: dict, provider_registry: dict[str, ProviderFactory]):
        self._agents: dict[str, AgentModelPolicy] = {
            agent_name: AgentModelPolicy(
                agent_name=agent_name,
                provider=cfg["provider"],
                model=cfg["model"],
                temperature=cfg.get("temperature", 0.2),
            )
            for agent_name, cfg in policy.get("agents", {}).items()
        }
        self._fallback_chain: list[str] = policy.get("fallback_chain", [])
        self._provider_registry = provider_registry

    @classmethod
    def from_yaml(cls, path: str | Path, provider_registry: dict[str, ProviderFactory]) -> "ModelRouter":
        with open(path) as f:
            policy = yaml.safe_load(f)
        return cls(policy, provider_registry)

    def policy_for(self, agent_name: str) -> AgentModelPolicy:
        try:
            return self._agents[agent_name]
        except KeyError as exc:
            raise KeyError(
                f"no model policy configured for agent {agent_name!r}; add it under `agents:` in the router YAML"
            ) from exc

    def providers_for(self, agent_name: str) -> list[LLMProvider]:
        """Primary provider for this agent, followed by the fallback chain
        (skipping the primary if it also appears in the chain), each built
        with the primary agent's model/temperature policy where relevant and
        the fallback providers' own default model otherwise."""
        policy = self.policy_for(agent_name)
        ordered_names = [policy.provider] + [p for p in self._fallback_chain if p != policy.provider]

        providers: list[LLMProvider] = []
        for provider_name in ordered_names:
            factory = self._provider_registry.get(provider_name)
            if factory is None:
                continue  # not configured in this deployment (e.g. no API key) — skip, don't crash
            model = policy.model if provider_name == policy.provider else None
            providers.append(factory(model, policy.temperature))
        if not providers:
            raise KeyError(
                f"no usable providers for agent {agent_name!r}: primary {policy.provider!r} and "
                f"fallback_chain {self._fallback_chain!r} all missing from the provider registry"
            )
        return providers
