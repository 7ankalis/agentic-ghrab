"""
Pipeline orchestrator — the deterministic-first analysis entry point.

Deterministic layer (GRS scoring, capability classification, reachability graph,
autonomous attack-path discovery) always runs, is instant, and needs no API key.
The AI layer (path validation/narration, cross-path toxic combinations, compliance
briefing, executive synthesis) runs only when a provider is connected. The two are
split into separate functions on purpose: `compute_deterministic` is cheap enough
to call on every request, while `run_ai_layer` spends tokens and is only ever
invoked from api/state.py's persisted-run flow (see db/repository.py) — never as
a side effect of a plain GET. Per-finding remediation enrichment is intentionally
on-demand (findings drill-in), not in this bulk pass.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

import networkx as nx
import pandas as pd

from agents.analyst_agent import detect_attack_paths
from agents.compliance_agent import compliance_summary
from agents.correlation_agent import find_toxic_combinations
from agents.discovery_agent import analyze as analyze_paths
from agents.triage_agent import executive_synthesis
from core.attack_graph import DiscoveredPath, HostNode, discover_paths
from core.capability import Capability, classify_all
from core.cmdb import CMDB, get_cmdb
from core.graph import Chain, build_chains
from core.ingestion import get_vulnerabilities


class RunCancelled(Exception):
    """Raised inside the pipeline when the operator hits the kill switch.
    Cancellation is cooperative: the AI layer checks `should_cancel()` at every
    agent boundary, so a kill takes effect at the next stage rather than
    tearing down a provider call mid-flight."""


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
    detected: dict = field(default_factory=dict)   # Analyst Detection Agent — paths reasoned from grounding alone
    correlation: dict = field(default_factory=dict)
    compliance: dict = field(default_factory=dict)
    executive_summary: str = ""
    generated_at: float = 0.0
    remediations: dict = field(default_factory=dict)  # qid -> enrich_remediation() result, cached for the session


def compute_deterministic(progress_cb=None) -> AnalysisResult:
    """The instant, no-API-key-needed half of the pipeline. Safe to call on
    every request — never spends a token, never touches the database."""
    def report(msg: str, level: str = "info"):
        if progress_cb:
            progress_cb(msg, level)

    report("Ingesting vulnerability export + computing GRS for every finding…")
    df = get_vulnerabilities()

    report("Parsing enterprise CMDB (zones, assets, trust levels, teams)…")
    cmdb = get_cmdb()

    report("Classifying findings into attacker capabilities (ATT&CK-style)…")
    caps = classify_all(df)

    report("Discovering attack paths from the reachability graph…")
    paths, graph, nodes = discover_paths(df, cmdb, caps)
    documented = build_chains(df)   # held-out oracle, verification overlay only — never fed to any agent

    return AnalysisResult(
        df=df, cmdb=cmdb, caps=caps, paths=paths, graph=graph, nodes=nodes,
        documented_chains=documented, ai_enabled=False, generated_at=time.time(),
    )


def run_ai_layer(result: AnalysisResult, session_state=None, progress_cb=None,
                 should_cancel=None) -> None:
    """Runs the token-spending agents and mutates `result` in place. Callers
    are expected to persist the outcome (see api/state.run_new_analysis) —
    this function has no caching of its own.

    `should_cancel`, if given, is polled at every agent boundary; when it
    returns True the pipeline stops between stages by raising RunCancelled."""
    def report(msg: str, level: str = "info"):
        if progress_cb:
            progress_cb(msg, level)

    def checkpoint():
        if should_cancel and should_cancel():
            raise RunCancelled

    df, cmdb, paths = result.df, result.cmdb, result.paths

    checkpoint()
    report("Analyst Detection Agent: reasoning attack paths from asset+ownership+"
           "reachability grounding (no candidate list, no answer key)…")
    result.detected = detect_attack_paths(df, cmdb, result.caps, result.nodes, session_state)
    if result.detected.get("error"):
        report(f"Analyst Detection Agent — provider error: {result.detected['error']}", "warn")

    checkpoint()
    report("Discovery Agent: validating, ranking, and narrating attack chains…")
    result.discovery = analyze_paths(paths, df, cmdb, session_state)
    disc_err = result.discovery.get("paths_error") or result.discovery.get("combos_error")
    if disc_err:
        report(f"Discovery Agent — provider error, deterministic chains still stand: {disc_err}", "warn")

    checkpoint()
    report("Correlation Agent: cross-referencing findings, assets, and teams…")
    result.correlation = find_toxic_combinations(df, cmdb, session_state)
    if result.correlation.get("error"):
        report(f"Correlation Agent — provider error: {result.correlation['error']}", "warn")

    checkpoint()
    report("Compliance Agent: building regulatory posture briefing…")
    result.compliance = compliance_summary(df, cmdb, session_state)
    if result.compliance.get("error"):
        report(f"Compliance Agent — provider error: {result.compliance['error']}", "warn")

    checkpoint()
    report("Triage Agent: drafting executive synthesis…")
    result.executive_summary = executive_synthesis(
        df, cmdb, session_state,
        discovery=result.discovery, correlation=result.correlation, compliance=result.compliance,
    )
    if result.executive_summary.startswith("AI executive synthesis unavailable"):
        report(f"Triage Agent — provider error: {result.executive_summary}", "warn")

    # Persist the Analyst Detection Agent's output inside the discovery blob so it
    # round-trips through the existing analysis_run schema (no dedicated column /
    # migration needed); api/state._attach_ai splits it back out on rehydrate.
    result.discovery["ai_detected"] = result.detected.get("detected_paths", [])
    if result.detected.get("error"):
        result.discovery["ai_detected_error"] = result.detected["error"]

    report("Analysis complete.")
