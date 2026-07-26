"""
Invariant #1: the oracle / documented paths / Attack_Path_Ref must NEVER reach a
classifier, graph builder, or agent prompt. The whole value proposition is that
the system *rediscovers* paths from grounding; the oracle exists only to score
detection (eval/) and drive the verification overlay.

This test captures the real (system, user) prompt of every agent in the pipeline
by patching the single LLM chokepoint (agents.base.call_llm / call_llm_json),
running the full AI layer with a stub provider, and asserting no answer-key token
appears in any prompt. It also asserts the answer key was severed from the
ingested finding schema itself.
"""
from __future__ import annotations

import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # backend/ on path

import pytest  # noqa: E402

from agents import base as agent_base  # noqa: E402
from agents.orchestrator import compute_deterministic, run_ai_layer  # noqa: E402
from core import config, datasets  # noqa: E402
from core.cmdb import reset_cmdb  # noqa: E402
from core.graph import build_chains  # noqa: E402
from core.ingestion import reset_vulnerabilities  # noqa: E402
from core.oracle import attack_path_refs  # noqa: E402
from eval.detection import datasets_with_oracle  # noqa: E402


def _forbidden_tokens(key: str, df) -> set[str]:
    """Every string that only the answer key knows: the per-finding
    Attack_Path_Ref values (e.g. 'PATH-A-Step1'), the bare documented path ids
    ('PATH-A'..), and the severed column name itself."""
    refs = attack_path_refs(key)
    tokens = {v for v in refs.values() if v}
    tokens |= {c.path_id for c in build_chains(df)}
    tokens.add("Attack_Path_Ref")
    return {t for t in tokens if t}


def _capture_agent_prompts(monkeypatch) -> list[tuple[str, str]]:
    """Patch the LLM chokepoint every agent funnels through and record each
    (system, user) prompt instead of calling a provider."""
    captured: list[tuple[str, str]] = []

    def fake_call_llm(role, system_prompt, user_prompt, *a, **k):
        captured.append((system_prompt, user_prompt))
        return types.SimpleNamespace(text="ok", provider="stub", model="stub")

    def fake_call_llm_json(role, system_prompt, user_prompt, *a, **k):
        captured.append((system_prompt, user_prompt))
        return {}

    monkeypatch.setattr(agent_base, "call_llm", fake_call_llm)
    monkeypatch.setattr(agent_base, "call_llm_json", fake_call_llm_json)
    return captured


@pytest.mark.parametrize("key", datasets_with_oracle())
def test_answer_key_severed_from_ingested_schema(key):
    datasets.set_active(key)
    reset_vulnerabilities()
    reset_cmdb()
    result = compute_deterministic()
    assert "Attack_Path_Ref" not in result.df.columns, (
        f"{key}: Attack_Path_Ref is still a column in the ingested findings — the "
        f"answer key must live only in the held-out oracle")


@pytest.mark.parametrize("key", datasets_with_oracle())
def test_no_oracle_text_in_any_agent_prompt(key, monkeypatch):
    datasets.set_active(key)
    reset_vulnerabilities()
    reset_cmdb()
    result = compute_deterministic()
    forbidden = _forbidden_tokens(key, result.df)
    assert forbidden, f"{key}: expected some oracle tokens to guard against"

    # The capability step calls providers directly (not via the captured
    # agents.base chokepoint); pin it to regex so the test stays offline and fast.
    # Its prompt only ever contains a single finding's own text, never the oracle.
    monkeypatch.setattr(config, "CAPABILITY_LLM_ENABLED", False)

    captured = _capture_agent_prompts(monkeypatch)
    run_ai_layer(result)  # stubbed provider — exercises every agent's prompt build
    assert captured, "no agent prompts were captured — the pipeline did not run"

    for system, user in captured:
        blob = f"{system}\n{user}"
        leaked = sorted(t for t in forbidden if t in blob)
        assert not leaked, (f"{key}: oracle tokens {leaked} leaked into an agent "
                            f"prompt — the answer key reached the model")
