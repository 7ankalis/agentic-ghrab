"""Server-side analysis state + runtime settings.

There is no per-request Streamlit session here, so `runtime_settings` plays the
role `st.session_state` used to: it holds operator-supplied API keys and
agent→provider overrides, and is passed to the pipeline/agents as `session_state`.
The computed AnalysisResult is memoised so the deterministic engine + AI
enrichment aren't recomputed on every request.
"""
from __future__ import annotations

import threading

from agents.orchestrator import AnalysisResult, run_pipeline

# Mimics st.session_state: keys like "apikey_<provider>", "agent_provider_<role>".
runtime_settings: dict = {}

_analysis: AnalysisResult | None = None
_lock = threading.Lock()


def get_analysis(force_refresh: bool = False, progress_cb=None) -> AnalysisResult:
    global _analysis
    with _lock:
        if _analysis is None or force_refresh:
            _analysis = run_pipeline(
                session_state=runtime_settings,
                force_refresh=force_refresh,
                progress_cb=progress_cb,
            )
        return _analysis


def invalidate() -> None:
    global _analysis
    with _lock:
        _analysis = None
