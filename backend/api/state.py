"""Server-side analysis state + runtime settings, backed by db/repository.py.

There is no per-request Streamlit session here, so `runtime_settings` plays the
role `st.session_state` used to: it holds operator-supplied API keys and
agent→provider overrides, and is passed to the pipeline/agents as `session_state`.

Every completed run (deterministic + whatever AI layer ran) is persisted as an
`analysis_run` row — see db/models.py — keyed by dataset + input fingerprint.
This module resolves what the SPA should currently see:

  - get_analysis()        — the active in-memory result; on a cold boot it
                             rehydrates from the last persisted run instead of
                             coming up blank.
  - check_duplicate()      — has this exact input already been analyzed? Lets
                             the caller (api/streams.py) show a reuse/refresh
                             card instead of silently re-running the AI layer.
  - run_new_analysis()      — always executes fresh and persists a new run.
  - reuse_run()              — adopts a previously persisted run as active
                                 without touching the agent chain at all.
"""
from __future__ import annotations

import threading

from agents.orchestrator import (
    AnalysisResult, RunCancelled, compute_deterministic, run_ai_layer,
)
from api import serializers as S
from core.config import active_dataset_key
from core.fingerprint import compute_input_fingerprint
from core.providers import any_provider_configured
from db import repository

# Mimics st.session_state: keys like "apikey_<provider>", "agent_provider_<role>".
runtime_settings: dict = {}

_current: AnalysisResult | None = None
_current_run_id: str | None = None
_lock = threading.Lock()


def _attach_ai(result: AnalysisResult, run) -> None:
    result.ai_enabled = run.ai_enabled
    result.discovery = run.discovery or {}
    result.correlation = run.correlation or {}
    result.compliance = run.compliance or {}
    result.executive_summary = run.executive_summary or ""


def get_analysis(progress_cb=None) -> AnalysisResult:
    """The currently active analysis. Never triggers the AI layer — that only
    ever happens inside run_new_analysis(), which is reached exclusively via
    the explicit POST /api/analyze action."""
    global _current, _current_run_id
    with _lock:
        if _current is not None:
            return _current
        result = compute_deterministic(progress_cb=progress_cb)
        result.ai_enabled = any_provider_configured(runtime_settings)
        run = repository.latest_complete_run(active_dataset_key())
        if run is not None:
            _attach_ai(result, run)
            _current_run_id = run.id
        _current = result
        return _current


def current_run_id() -> str | None:
    return _current_run_id


def check_duplicate(force_refresh: bool) -> dict | None:
    """If the input is byte-identical to the dataset's latest completed run,
    return that run's summary so the caller can offer reuse instead of
    silently re-spending LLM calls. None means "go ahead and run"."""
    if force_refresh:
        return None
    run = repository.latest_complete_run(active_dataset_key(), compute_input_fingerprint())
    return run.summary() if run is not None else None


def run_new_analysis(force_refresh: bool = False, progress_cb=None,
                     should_cancel=None) -> AnalysisResult:
    """Always computes fresh (deterministic, plus the AI layer if a provider
    is configured) and persists the outcome as a new analysis_run.

    `should_cancel`, if given, is polled between AI agents so the operator's
    kill switch can abort the run; a cancelled run is recorded as failed and
    never becomes the active analysis."""
    global _current, _current_run_id
    fingerprint = compute_input_fingerprint()
    ai_enabled = any_provider_configured(runtime_settings)
    run = repository.create_run(active_dataset_key(), fingerprint, ai_enabled)

    result = compute_deterministic(progress_cb=progress_cb)
    result.ai_enabled = ai_enabled
    try:
        if ai_enabled:
            run_ai_layer(result, runtime_settings, progress_cb=progress_cb,
                         should_cancel=should_cancel)
        else:
            if progress_cb:
                progress_cb("Deterministic analysis complete (no AI provider connected).")
        repository.complete_run(
            run.id,
            discovery=result.discovery, correlation=result.correlation,
            compliance=result.compliance, executive_summary=result.executive_summary,
            kpi_snapshot=S.kpis(result), ai_enabled=ai_enabled,
        )
    except RunCancelled:
        repository.fail_run(run.id, "Cancelled by operator")
        raise
    except Exception as exc:  # noqa: BLE001
        repository.fail_run(run.id, str(exc))
        raise

    with _lock:
        _current = result
        _current_run_id = run.id
    return result


def reuse_run(run_id: str) -> AnalysisResult:
    """Adopts a previously persisted run as active — the deterministic layer
    is recomputed (cheap, always fresh), the AI layer is loaded straight from
    that run's stored blobs. No agent is invoked."""
    global _current, _current_run_id
    run = repository.get_run(run_id)
    if run is None or run.status != "complete":
        raise ValueError(f"No completed run {run_id!r}")
    result = compute_deterministic()
    _attach_ai(result, run)
    with _lock:
        _current = result
        _current_run_id = run.id
    return result


def invalidate() -> None:
    """Drops the in-memory analysis (e.g. provider settings changed). The
    next get_analysis() cold-hydrates from the last persisted run again."""
    global _current, _current_run_id
    with _lock:
        _current = None
        _current_run_id = None


def switch_dataset(key: str):
    """Make `key` the active enterprise: flush the cached vulnerabilities +
    CMDB (they hold the previous dataset), then drop the in-memory analysis so
    the next get_analysis() rebuilds against the new dataset and rehydrates
    from that dataset's own persisted run history. Returns the new Dataset."""
    from core import datasets
    from core.cmdb import reset_cmdb
    from core.ingestion import reset_vulnerabilities

    ds = datasets.set_active(key)  # raises KeyError for an unknown key
    reset_vulnerabilities()
    reset_cmdb()
    invalidate()
    return ds
