"""Agent 6 — Compliance & Governance Mapping (non-AI, template-driven).

Maps every finding to the regulatory frameworks it falls under, using two
ground-truth sources already in the pipeline rather than inventing a
mapping: the CSV's own `Compliance_Ref` column (free text like
"PCI DSS 1.3.1 / NIST SC-7") and the zone-level `compliance_scope` Agent 1
already derived from architecture.md (assets in the CDE/SWIFT-scoped zone
inherit that scope even when a specific finding's own CSV row doesn't spell
out a control id). DORA CIF scope is already computed per-finding in
Agent 5 (ghrab_risk_methodology.md §7) and folded in here as its own
framework bucket for a single unified compliance register.
"""

from __future__ import annotations

import re

from vmc.models import Asset, ComplianceFinding, Finding, RiskAssessment

_FRAMEWORK_KEYWORDS: dict[str, str] = {
    "pci": "PCI DSS",
    "swift": "SWIFT CSP",
    "nist": "NIST",
    "iso": "ISO 27001",
}


def _classify_ref(ref: str) -> tuple[str, str] | None:
    lowered = ref.lower()
    for keyword, framework in _FRAMEWORK_KEYWORDS.items():
        if keyword in lowered:
            control_id = ref.strip()
            return framework, control_id
    return None


def _frameworks_for_finding(finding: Finding, asset: Asset | None, dora_cif_scope: bool) -> dict[str, list[str]]:
    frameworks: dict[str, list[str]] = {}

    for raw_ref in finding.compliance_refs:
        for token in re.split(r"[/;]", raw_ref):
            token = token.strip()
            if not token:
                continue
            classified = _classify_ref(token)
            if classified:
                framework, control_id = classified
                frameworks.setdefault(framework, [])
                if control_id not in frameworks[framework]:
                    frameworks[framework].append(control_id)

    if asset is not None:
        for scope in asset.compliance_scope:
            classified = _classify_ref(scope)
            framework = classified[0] if classified else scope
            frameworks.setdefault(framework, [])

    if dora_cif_scope:
        frameworks.setdefault("DORA (CIF scope)", [])

    return frameworks


def run_agent6(
    findings: list[Finding], assets: dict[str, Asset], risk_register: dict[str, RiskAssessment]
) -> dict[str, ComplianceFinding]:
    register: dict[str, ComplianceFinding] = {}
    for finding in findings:
        asset = assets.get(finding.asset_hostname) or assets.get(finding.asset_ip)
        assessment = risk_register.get(finding.finding_id)
        dora_cif_scope = bool(assessment and assessment.dora_cif_scope)
        frameworks = _frameworks_for_finding(finding, asset, dora_cif_scope)
        if frameworks:
            register[finding.finding_id] = ComplianceFinding(finding_id=finding.finding_id, frameworks=frameworks)
    return register


def framework_rollup(
    compliance_register: dict[str, ComplianceFinding], risk_register: dict[str, RiskAssessment]
) -> dict[str, dict]:
    """One rollup row per framework: total findings in scope, how many are
    still open at IMMEDIATE/ACT (i.e. not yet on track), and the worst GRS
    score in scope — everything the Compliance view needs, pre-aggregated."""
    rollup: dict[str, dict] = {}
    for finding_id, cf in compliance_register.items():
        assessment = risk_register.get(finding_id)
        for framework in cf.frameworks:
            row = rollup.setdefault(
                framework, {"framework": framework, "finding_count": 0, "urgent_count": 0, "worst_score": 0.0}
            )
            row["finding_count"] += 1
            if assessment:
                if assessment.band in ("IMMEDIATE", "ACT"):
                    row["urgent_count"] += 1
                row["worst_score"] = max(row["worst_score"], assessment.score)
    return rollup
