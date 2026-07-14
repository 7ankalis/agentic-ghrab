"""Shared Pydantic data model for VMC.

Field-level shapes for `Finding`, `Asset`, `ThreatIntel`, and `RiskAssessment`
follow VMC_ARCHITECTURE_OVERVIEW.md §6 exactly — they were designed against
the real sample dataset's column structure and should not be changed casually.
Every other type here is a Phase-1 best-effort shape for the `ExposureContext`
fields that later agents (3-9) will own; expect them to be refined once those
agents are built.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Agent 1 output
# ---------------------------------------------------------------------------


class Finding(BaseModel):
    finding_id: str
    cve_id: str | None = None
    category: str  # Missing Patch / Misconfiguration / Excessive Access / Cloud Misconfig / Compliance Gap
    title: str
    severity_raw: str
    cvss_score: float | None = None
    cvss_vector: str | None = None
    asset_ip: str
    asset_hostname: str
    vlan_id: str | None = None
    zone: str
    port: str | None = None
    description: str = ""
    consequence: str = ""
    remediation_text: str = ""
    patch_available: bool | None = None
    responsible_team: str
    # Raw scanner-export ground truth (only present in the synthetic Ghrab
    # dataset's Attack_Path_Ref column; a real Qualys/Nessus/Rapid7 export
    # never has this). Ingested for transparency/audit only — Agent 4's
    # attack-path discovery (agents/attack_paths.py) never reads this field,
    # so its output is never leaking the answer key.
    attack_path_refs: list[str] = Field(default_factory=list)
    compliance_refs: list[str] = Field(default_factory=list)
    status: str = "Open"


class Asset(BaseModel):
    hostname: str
    ip: str
    vlan_id: str | None = None
    zone: str
    owning_team: str
    criticality_tier: int  # 0 = crown jewel .. 3 = general purpose
    compliance_scope: list[str] = Field(default_factory=list)
    acw: float = 0.4  # Asset Criticality Weight, 0.0-1.0 (ghrab_risk_methodology.md §3)


class TeamInfo(BaseModel):
    team_id: str
    name: str
    owned_zones: list[str] = Field(default_factory=list)
    owned_assets: list[str] = Field(default_factory=list)


class DataQualityIssue(BaseModel):
    issue_type: Literal["orphaned_ip", "ambiguous_ownership", "unparseable_row", "other"]
    finding_id: str | None = None
    raw_row: dict[str, str] | None = None
    detail: str


# ---------------------------------------------------------------------------
# Agent 2 output
# ---------------------------------------------------------------------------


class NetworkZone(BaseModel):
    zone_id: str
    name: str
    vlan_ids: list[str] = Field(default_factory=list)
    owning_team: str | None = None
    compliance_scope: list[str] = Field(default_factory=list)
    trust_level_raw: str | None = None  # as written in architecture.md's "Trust Level" column, e.g. "Low (internet-facing)"
    exposure_tier: float = 0.90  # multiplier, ghrab_risk_methodology.md §5 (default: Internal) — set by Agent 2


class TrustEdge(BaseModel):
    source_zone: str
    target_zone: str
    description: str = ""
    documented: bool = True  # False if only inferred/observed, not written in architecture.md


class NetworkGraph(BaseModel):
    zones: dict[str, NetworkZone] = Field(default_factory=dict)
    trust_edges: list[TrustEdge] = Field(default_factory=list)


class SegmentationFinding(BaseModel):
    finding_id: str
    source_zone: str
    target_zone: str
    issue_description: str
    health: Literal["Green", "Yellow", "Red"]
    remediation: str = ""


# ---------------------------------------------------------------------------
# Agent 3 output
# ---------------------------------------------------------------------------


class ThreatIntel(BaseModel):
    cve_id: str
    epss_score: float | None = None
    in_kev: bool = False
    exploit_maturity: Literal["weaponized", "poc", "theoretical", "unknown"] = "unknown"
    sources: list[str] = Field(default_factory=list)
    fetched_at: datetime


# ---------------------------------------------------------------------------
# Agent 4 output
# ---------------------------------------------------------------------------


class AttackPathStep(BaseModel):
    step_ref: str  # e.g. "PATH-E-Step2"
    finding_id: str | None = None
    description: str


class AttackPath(BaseModel):
    path_ref: str  # e.g. "PATH-E"
    steps: list[AttackPathStep] = Field(default_factory=list)
    target_asset: str | None = None
    summary: str = ""


class ChokePoint(BaseModel):
    finding_id: str
    paths_collapsed: list[str] = Field(default_factory=list)
    rationale: str = ""


# ---------------------------------------------------------------------------
# Agent 5 output — the core product
# ---------------------------------------------------------------------------


class RiskAssessment(BaseModel):
    finding_id: str
    score: float  # 0-100, deterministic — the Ghrab Risk Score (GRS)
    score_breakdown: dict[str, float] = Field(default_factory=dict)  # every weighted term, auditable
    band: Literal["IMMEDIATE", "ACT", "ATTEND", "TRACK*", "TRACK"]  # SSVC-aligned action band, GRS §7
    sla_days: int | None  # default SLA for the band, capped by the DORA overlay when applicable; None = monitor only
    dora_cif_scope: bool = False  # asset is in a DORA "critical or important function" scope, GRS §7
    ai_explanation: str = ""  # plain-English, clearly separate from the score itself
    policy_version: str


# ---------------------------------------------------------------------------
# Agent 6 output
# ---------------------------------------------------------------------------


class ComplianceFinding(BaseModel):
    finding_id: str
    frameworks: dict[str, list[str]] = Field(default_factory=dict)  # framework -> control ids


# ---------------------------------------------------------------------------
# Agent 7 output
# ---------------------------------------------------------------------------


class TeamBrief(BaseModel):
    """One team's remediation queue: real findings, real GRS scores, real
    CSV-sourced remediation text — no invented effort estimates or
    schedules, since we have no grounding for those (see agents/routing.py)."""

    team_id: str
    team_name: str
    total_findings: int
    band_counts: dict[str, int] = Field(default_factory=dict)
    choke_point_count: int = 0
    top_finding_ids: list[str] = Field(default_factory=list)  # sorted by GRS descending
    brief_text: str = ""


# ---------------------------------------------------------------------------
# Agent 8 output
# ---------------------------------------------------------------------------


class SLAStatus(BaseModel):
    finding_id: str
    due_date: datetime | None = None
    days_remaining: int | None = None
    breached: bool = False


class RiskForecast(BaseModel):
    horizon_days: int
    projected_open_findings: list[int] = Field(default_factory=list)
    projected_risk_score: list[float] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Agent 9 output
# ---------------------------------------------------------------------------


class DashboardBundle(BaseModel):
    triage_rows: list[dict] = Field(default_factory=list)
    attack_path_graph: dict = Field(default_factory=dict)
    team_boards: dict[str, list[dict]] = Field(default_factory=dict)
    compliance_reports: dict[str, str] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Meta
# ---------------------------------------------------------------------------


class AgentLog(BaseModel):
    agent_name: str
    started_at: datetime
    finished_at: datetime | None = None
    status: Literal["running", "ok", "degraded", "failed"] = "running"
    detail: str = ""


class AgentError(BaseModel):
    agent_name: str
    error_type: str
    message: str
    occurred_at: datetime


class ExposureContext(BaseModel):
    run_id: str
    tenant_id: str

    # Agent 1 output
    findings: list[Finding] = Field(default_factory=list)
    assets: dict[str, Asset] = Field(default_factory=dict)
    teams: dict[str, TeamInfo] = Field(default_factory=dict)
    data_quality_issues: list[DataQualityIssue] = Field(default_factory=list)

    # Agent 2 output
    topology: NetworkGraph = Field(default_factory=NetworkGraph)
    segmentation_findings: list[SegmentationFinding] = Field(default_factory=list)
    diagram_vs_markdown_conflicts: list[str] = Field(default_factory=list)

    # Agent 3 output
    enrichment: dict[str, ThreatIntel] = Field(default_factory=dict)

    # Agent 4 output
    attack_paths: dict[str, AttackPath] = Field(default_factory=dict)
    choke_points: list[ChokePoint] = Field(default_factory=list)

    # Agent 5 output
    risk_register: dict[str, RiskAssessment] = Field(default_factory=dict)

    # Agent 6 output
    compliance_register: dict[str, ComplianceFinding] = Field(default_factory=dict)

    # Agent 7 output
    team_briefs: dict[str, TeamBrief] = Field(default_factory=dict)

    # Agent 8 output
    sla_dashboard: dict[str, SLAStatus] = Field(default_factory=dict)
    risk_trend_forecast: RiskForecast | None = None

    # Agent 9 output
    dashboard_bundle: DashboardBundle | None = None

    # Meta
    agent_logs: list[AgentLog] = Field(default_factory=list)
    errors: list[AgentError] = Field(default_factory=list)
    timing_ms: dict[str, float] = Field(default_factory=dict)
