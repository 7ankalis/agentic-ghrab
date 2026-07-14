"""
Pipeline orchestrator — the deterministic-first analysis entry point.

Deterministic layer (GRS scoring, capability classification, reachability graph,
autonomous attack-path discovery) always runs, is instant, and needs no API key.
The AI layer (path validation/narration, cross-path toxic combinations, compliance
briefing, executive synthesis) runs only when a provider is connected and is
cached to disk so repeat runs don't re-spend tokens unless a refresh is forced.
Per-finding remediation enrichment is intentionally on-demand (findings drill-in),
not in this bulk pass.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field

import networkx as nx
import pandas as pd

from agents.compliance_agent import compliance_summary
from agents.correlation_agent import find_toxic_combinations
from agents.discovery_agent import analyze as analyze_paths
from agents.triage_agent import executive_synthesis
from core.attack_graph import DiscoveredPath, HostNode, discover_paths
from core.capability import Capability, classify_all
from core.cmdb import CMDB, get_cmdb
from core.config import ANALYSIS_CACHE_PATH
from core.graph import Chain, build_chains
from core.ingestion import get_vulnerabilities
from core.providers import any_provider_configured


@dataclass
class AnalysisResult:
    df: pd.DataFrame
    cmdb: CMDB
    caps: dict[int, Capability]
    paths: list[DiscoveredPath]
    graph: nx.DiGraph
    nodes: dict[str, HostNode]
    documented_chains: list[Chain]        # from Attack_Path_Ref, for the discovered/documented overlay
    ai_enabled: bool
    discovery: dict = field(default_factory=dict)
    correlation: dict = field(default_factory=dict)
    compliance: dict = field(default_factory=dict)
    executive_summary: str = ""
    generated_at: float = 0.0


def _load_cache() -> dict:
    if ANALYSIS_CACHE_PATH.exists():
        try:
            return json.loads(ANALYSIS_CACHE_PATH.read_text())
        except Exception:  # noqa: BLE001
            return {}
    return {}


def _save_cache(payload: dict) -> None:
    ANALYSIS_CACHE_PATH.write_text(json.dumps(payload, indent=2, default=str))


def run_pipeline(session_state=None, force_refresh: bool = False,
                 progress_cb=None) -> AnalysisResult:
    def report(msg: str):
        if progress_cb:
            progress_cb(msg)

    report("Ingesting vulnerability export + computing GRS for every finding…")
    df = get_vulnerabilities()

    report("Parsing enterprise CMDB (zones, assets, trust levels, teams)…")
    cmdb = get_cmdb()

    report("Classifying findings into attacker capabilities (ATT&CK-style)…")
    caps = classify_all(df)

    report("Discovering attack paths from the reachability graph…")
    paths, graph, nodes = discover_paths(df, cmdb, caps)
    documented = build_chains(df)   # oracle/overlay only — never fed to discovery

    ai_enabled = any_provider_configured(session_state)
    result = AnalysisResult(
        df=df, cmdb=cmdb, caps=caps, paths=paths, graph=graph, nodes=nodes,
        documented_chains=documented, ai_enabled=ai_enabled, generated_at=time.time(),
    )
    if not ai_enabled:
        report("Deterministic analysis complete (no AI provider connected).")
        return result

    cache = {} if force_refresh else _load_cache()
    if cache and not force_refresh and cache.get("discovery"):
        result.discovery = cache.get("discovery", {})
        result.correlation = cache.get("correlation", {})
        result.compliance = cache.get("compliance", {})
        result.executive_summary = cache.get("executive_summary", "")
        report("Loaded cached AI enrichment.")
        return result

    report("Discovery Agent: validating, ranking, and narrating attack chains…")
    result.discovery = analyze_paths(paths, df, cmdb, session_state)

    report("Correlation Agent: cross-referencing findings, assets, and teams…")
    result.correlation = find_toxic_combinations(df, cmdb, session_state)

    report("Compliance Agent: building regulatory posture briefing…")
    result.compliance = compliance_summary(df, cmdb, session_state)

    report("Triage Agent: drafting executive synthesis…")
    result.executive_summary = executive_synthesis(df, cmdb, session_state)

    _save_cache({
        "discovery": result.discovery,
        "correlation": result.correlation,
        "compliance": result.compliance,
        "executive_summary": result.executive_summary,
    })
    report("Analysis complete.")
    return result
