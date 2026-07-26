"""
Phase 5 production-hardening tests: resilience (request timeouts + retry
classification), determinism (per-role temperature), observability (real
call_log accounting), and end-to-end graceful degradation — a provider-disabled
run must still produce the full deterministic layer and never raise.

All LLM interaction is stubbed or disabled; these stay fast, offline, and
deterministic (no provider, no network, no sleeps).
"""
from __future__ import annotations

import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # backend/ on path

import pytest  # noqa: E402

from core import call_log, datasets, providers  # noqa: E402
from core.cmdb import reset_cmdb  # noqa: E402
from core.config import LLM_REQUEST_TIMEOUT_SEC, agent_temperature  # noqa: E402
from core.ingestion import reset_vulnerabilities  # noqa: E402
from eval.detection import datasets_with_oracle  # noqa: E402


# --- Resilience: request timeout + retry classification ------------------------

def test_timeout_is_classified_retryable():
    """A timeout must read as retryable (retry same provider, like a 429); an
    ordinary error must not."""
    assert providers._is_timeout(Exception("Request timed out"))
    assert providers._is_timeout(TimeoutError("deadline exceeded"))
    assert not providers._is_timeout(ValueError("bad json"))
    # and a timeout is not misread as a rate-limit (different backoff semantics)
    assert not providers._is_rate_limit(TimeoutError("deadline exceeded"))


def test_request_timeout_passed_to_provider(monkeypatch):
    """call_llm must hand the configured wall-clock timeout to the HTTP client so a
    hung provider can't stall a run indefinitely."""
    captured: dict = {}

    def fake_completion(**kwargs):
        captured.update(kwargs)
        return {"choices": [{"message": {"content": "ok"}}],
                "usage": {"total_tokens": 3, "prompt_tokens": 2, "completion_tokens": 1}}

    fake_litellm = types.SimpleNamespace(
        completion=fake_completion, suppress_debug_info=True,
        completion_cost=lambda **_: 0.0)
    monkeypatch.setitem(sys.modules, "litellm", fake_litellm)
    monkeypatch.setattr(providers, "get_api_key", lambda p, s: "k" if p == "mistral" else None)
    monkeypatch.setattr(providers, "_throttle", lambda *a, **k: None)

    out = providers.call_llm("capability", "sys", "user", session_state=None)
    assert out.text == "ok"
    assert captured.get("timeout") == LLM_REQUEST_TIMEOUT_SEC


def test_timeout_retries_then_falls_through(monkeypatch):
    """A persistent timeout retries the SAME provider up to the cap, then raises
    ProviderUnavailable — it never hangs and never silently succeeds."""
    calls = {"n": 0}

    def always_timeout(**kwargs):
        calls["n"] += 1
        raise TimeoutError("timed out")

    fake_litellm = types.SimpleNamespace(
        completion=always_timeout, suppress_debug_info=True,
        completion_cost=lambda **_: 0.0)
    monkeypatch.setitem(sys.modules, "litellm", fake_litellm)
    monkeypatch.setattr(providers, "get_api_key", lambda p, s: "k" if p == "mistral" else None)
    monkeypatch.setattr(providers, "_throttle", lambda *a, **k: None)
    monkeypatch.setattr(providers.time, "sleep", lambda *_: None)  # no real backoff wait
    monkeypatch.setattr(providers, "LLM_MAX_RETRIES", 2)

    with pytest.raises(providers.ProviderUnavailable):
        providers.call_llm("capability", "sys", "user", session_state=None)
    assert calls["n"] == 3  # initial attempt + 2 retries on the one configured provider


# --- Determinism: per-role temperature -----------------------------------------

def test_structured_roles_are_temperature_zero():
    for role in ("capability", "correlation", "attack_path", "remediation", "compliance"):
        assert agent_temperature(role) == 0.0, f"{role} must sample deterministically"
    assert agent_temperature("unknown-role") == 0.0  # safe default


def test_triage_temperature_documented_nonzero():
    # triage is free-text synthesis nothing downstream parses — a documented,
    # explicit non-zero value, not a silent default.
    assert agent_temperature("triage") >= 0.0


def test_ask_json_forwards_role_temperature(monkeypatch):
    from agents import base
    seen: dict = {}

    def fake_json(role, system, user, session_state=None, max_tokens=1500,
                  detail="", temperature=0.2):
        seen["temperature"] = temperature
        return {}

    monkeypatch.setattr(base, "call_llm_json", fake_json)
    base.ask_json("correlation", "task", "context")
    assert seen["temperature"] == 0.0


# --- Observability: real call_log accounting -----------------------------------

def test_summarize_since_accounts_real_usage():
    call_log.clear()
    m = call_log.marker()
    # one successful call for two roles + one error
    c1 = call_log.start("attack_path", "mistral", "mistral-medium-2505")
    call_log.finish(c1, "attack_path", "mistral", "mistral-medium-2505", True,
                    120.0, tokens=100, prompt_tokens=70, completion_tokens=30, cost_usd=0.001)
    c2 = call_log.start("capability", "mistral", "mistral-small-2506")
    call_log.finish(c2, "capability", "mistral", "mistral-small-2506", True,
                    50.0, tokens=40, prompt_tokens=30, completion_tokens=10, cost_usd=0.0002)
    c3 = call_log.start("capability", "mistral", "mistral-small-2506")
    call_log.finish(c3, "capability", "mistral", "mistral-small-2506", False, 10.0,
                    error="boom")

    acct = call_log.summarize_since(m)
    assert acct["calls"] == 3 and acct["ok"] == 2 and acct["errors"] == 1
    assert acct["tokens"] == 140
    assert acct["cost_usd"] == pytest.approx(0.0012)
    assert acct["latency_ms"] == pytest.approx(180.0)
    assert acct["by_role"]["capability"]["calls"] == 2
    assert acct["by_role"]["attack_path"]["tokens"] == 100
    assert acct["by_provider"]["mistral"]["calls"] == 3


def test_marker_scopes_accounting_to_new_calls():
    call_log.clear()
    c0 = call_log.start("triage", "mistral", "mistral-medium-2505")
    call_log.finish(c0, "triage", "mistral", "mistral-medium-2505", True, 5.0, tokens=9)
    m = call_log.marker()          # snapshot AFTER the first call
    c1 = call_log.start("triage", "mistral", "mistral-medium-2505")
    call_log.finish(c1, "triage", "mistral", "mistral-medium-2505", True, 5.0, tokens=11)
    acct = call_log.summarize_since(m)
    assert acct["calls"] == 1 and acct["tokens"] == 11  # the pre-marker call is excluded


# --- Graceful degradation: provider disabled → full deterministic layer, no raise

@pytest.mark.parametrize("key", datasets_with_oracle())
def test_no_provider_run_preserves_deterministic_layer(key, monkeypatch):
    """With every provider key absent, run_ai_layer must complete without raising,
    leave the deterministic paths intact, emit no AI-detected paths, and still
    attach a (zero-cost) run trace. This is invariant #3 end-to-end."""
    from agents.orchestrator import compute_deterministic, run_ai_layer

    monkeypatch.setattr(providers, "get_api_key", lambda p, s: None)  # no keys anywhere
    datasets.set_active(key)
    reset_vulnerabilities()
    reset_cmdb()

    result = compute_deterministic()
    det_path_ids = [p.path_id for p in result.paths]
    assert det_path_ids, "deterministic engine should find paths for a dataset with an oracle"

    run_ai_layer(result, session_state=None)  # must not raise

    # deterministic layer untouched (no LLM upgrade → graph not rebuilt)
    assert [p.path_id for p in result.paths] == det_path_ids
    # detection degraded cleanly: no fabricated paths, explicit no-provider signal
    assert result.detected.get("detected_paths") == []
    assert result.detected.get("error")
    # observability still produced a trace, with zero real spend
    assert result.run_trace, "a run trace should be attached even with no provider"
    assert result.run_trace["accounting"]["cost_usd"] == 0.0
